import asyncio
import json
import os
import tempfile
import time
from datetime import datetime
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_current_user
from app.api.storage_sources import router as storage_sources_router
from app.database import Base, get_db
from app.models import AuditLogEntry, DSChunk, DSFile, DSLeakRecord, DSStorageSource, StorageSource, User
from app.services import deep_search_ingestion
from app.services.connectors import FileEntry
from app.services.deep_search_audit import DeepSearchAuditEvent
from app.services.deep_search_patterns import PATTERN_REGISTRY, scan_chunk
from app.services.storage_credential_vault import StorageCredentialVault
from app.tasks import deep_search_tasks

TEST_KEK_A = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
TEST_KEK_B = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA="


async def _build_session():
    fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory, db_path


def _encrypt_config(config: dict, kek: str = TEST_KEK_A) -> str:
    from app.services.crypto import encrypt

    return encrypt(json.dumps(StorageCredentialVault(kek_b64=kek).encrypt_credentials(config)))


async def _create_source_pair(
    session_factory,
    config: dict,
    *,
    enabled: bool = True,
    ds_enabled: bool = True,
    ds_credentials: dict | None = None,
    source_type: str = "localfs",
):
    async with session_factory() as db:
        source = StorageSource(
            name="Test Source",
            source_type=source_type,
            config_encrypted=_encrypt_config(config),
            is_enabled=enabled,
            schedule="@hourly",
            recursive=True,
            max_file_size_mb=25,
        )
        db.add(source)
        await db.flush()
        ds_source = DSStorageSource(
            id=source.id,
            display_name=source.name,
            source_type=source_type,
            enabled=ds_enabled,
            path=str(config.get("path", "")),
            max_file_size_mb=25,
            credentials=StorageCredentialVault(kek_b64=TEST_KEK_A).encrypt_credentials(ds_credentials or {}),
            include_extensions=[],
            exclude_extensions=[],
        )
        db.add(ds_source)
        await db.commit()
        return source.id


async def _fetch_all(session_factory, model):
    async with session_factory() as db:
        return list((await db.execute(select(model))).scalars().all())


@pytest.mark.asyncio
async def test_pipeline_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    text_path = tmp_path / "notes.txt"
    text_path.write_text("hello from deep search\n", encoding="utf-8")
    leak_path = tmp_path / "secret.txt"
    leak_path.write_text("key=AKIA1234567890ABCDEF\n", encoding="utf-8")
    binary_path = tmp_path / "blob.bin"
    binary_path.write_bytes(b"\x00\x01\x02\x03")

    engine, session_factory, db_path = await _build_session()
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    try:
        source_id = await _create_source_pair(session_factory, {"base_path": str(tmp_path)})
        summary = await deep_search_ingestion.ingest_source(source_id, triggered_by="test")

        files = await _fetch_all(session_factory, DSFile)
        chunks = await _fetch_all(session_factory, DSChunk)
        leaks = await _fetch_all(session_factory, DSLeakRecord)

        assert summary["status"] == "ok"
        assert len(files) == 3
        assert len(chunks) > 0
        assert len(leaks) == 1
        assert leaks[0].pattern_name == "aws_access_key_id"
        assert leaks[0].severity == 95
        leaked_file = next(file for file in files if file.file_path == "secret.txt")
        assert leaked_file.has_api_keys is True
        assert leaked_file.leak_count == 1
        assert next(file for file in files if file.file_path == "blob.bin").parse_mode == "empty"
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_up_to_date_skip_updates_last_seen_without_new_rows(tmp_path, monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    (tmp_path / "notes.txt").write_text("hello world\n", encoding="utf-8")

    engine, session_factory, db_path = await _build_session()
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    try:
        source_id = await _create_source_pair(session_factory, {"base_path": str(tmp_path)})
        await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        async with session_factory() as db:
            file_row = (await db.execute(select(DSFile))).scalar_one()
            first_seen = file_row.last_seen_at
        time.sleep(0.02)
        summary = await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        async with session_factory() as db:
            file_row = (await db.execute(select(DSFile))).scalar_one()
            assert file_row.last_seen_at > first_seen
            assert len((await db.execute(select(DSChunk))).scalars().all()) > 0
            assert len((await db.execute(select(DSLeakRecord))).scalars().all()) == 0
        assert summary["files_indexed"] == 0
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_content_hash_change_replaces_chunks_and_leaks(tmp_path, monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    target = tmp_path / "secret.txt"
    target.write_text("AKIA1234567890ABCDEF\n", encoding="utf-8")

    engine, session_factory, db_path = await _build_session()
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    try:
        source_id = await _create_source_pair(session_factory, {"base_path": str(tmp_path)})
        await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        async with session_factory() as db:
            old_file = (await db.execute(select(DSFile))).scalar_one()
            old_file_id = old_file.id
            assert len((await db.execute(select(DSLeakRecord))).scalars().all()) == 1

        target.write_text("updated content without keys\n", encoding="utf-8")
        future = time.time() + 5
        os.utime(target, (future, future))

        await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        async with session_factory() as db:
            files = list((await db.execute(select(DSFile))).scalars().all())
            new_file = files[0]
            chunks = list((await db.execute(select(DSChunk))).scalars().all())
            assert new_file.content_sha256 != old_file.content_sha256
            assert len((await db.execute(select(DSLeakRecord))).scalars().all()) == 0
            assert chunks
            assert all("AKIA1234567890ABCDEF" not in chunk.content for chunk in chunks)
            assert any("updated content without keys" in chunk.content for chunk in chunks)
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_path_traversal_reject_audits_and_continues(tmp_path, monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    safe_path = tmp_path / "safe.txt"
    safe_path.write_text("safe text\n", encoding="utf-8")

    class StubConnector:
        def list_files(self, path="", recursive=True, max_files=100_000):
            yield FileEntry(path="../../../etc/passwd", size=12)
            yield FileEntry(path="safe.txt", size=safe_path.stat().st_size, mtime=datetime.now())

        def get_file_bytes(self, file_path: str, max_bytes: int = 0) -> bytes:
            return safe_path.read_bytes()

    engine, session_factory, db_path = await _build_session()
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(deep_search_ingestion, "get_connector", lambda *args, **kwargs: StubConnector())
    try:
        source_id = await _create_source_pair(
            session_factory,
            {"base_path": str(tmp_path)},
            ds_credentials={"base_path": str(tmp_path)},
        )
        summary = await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        async with session_factory() as db:
            files = list((await db.execute(select(DSFile))).scalars().all())
            audits = list(
                (await db.execute(select(AuditLogEntry).where(AuditLogEntry.action == DeepSearchAuditEvent.FILE_PATH_REJECTED.value))).scalars().all()
            )
        assert summary["files_seen"] == 2
        assert len(files) == 1
        assert len(audits) == 1
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_kek_failure_fast_fails_without_connector(monkeypatch, tmp_path):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_B)
    engine, session_factory, db_path = await _build_session()
    connector_mock = Mock(side_effect=AssertionError("connector should not be created"))
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(deep_search_ingestion, "get_connector", connector_mock)
    try:
        source_id = await _create_source_pair(session_factory, {"base_path": str(tmp_path)})
        async with session_factory() as db:
            ds_source = (await db.execute(select(DSStorageSource).where(DSStorageSource.id == source_id))).scalar_one()
            ds_source.credentials = {}
            legacy = (await db.execute(select(StorageSource).where(StorageSource.id == source_id))).scalar_one()
            legacy.config_encrypted = _encrypt_config({"password": "topsecret", "base_path": str(tmp_path)}, kek=TEST_KEK_A)
            await db.commit()

        summary = await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        connector_mock.assert_not_called()
        assert summary["status"] == "error"
        assert "DS_CREDENTIAL_KEK" in summary["error_msg"]
        async with session_factory() as db:
            ds_source = (await db.execute(select(DSStorageSource).where(DSStorageSource.id == source_id))).scalar_one()
            audits = list(
                (await db.execute(
                    select(AuditLogEntry).where(AuditLogEntry.action == DeepSearchAuditEvent.SOURCE_INGEST_CREDENTIALS_ERROR.value)
                )).scalars().all()
            )
            assert ds_source.health_status == "error"
            assert len(audits) == 1
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_empty_binary_file_is_skipped_with_empty_parse_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\x03")

    engine, session_factory, db_path = await _build_session()
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    try:
        source_id = await _create_source_pair(session_factory, {"base_path": str(tmp_path)})
        await deep_search_ingestion.ingest_source(source_id, triggered_by="test")
        async with session_factory() as db:
            file_row = (await db.execute(select(DSFile))).scalar_one()
            assert file_row.parse_mode == "empty"
            assert file_row.index_status == "skipped"
            assert len((await db.execute(select(DSChunk))).scalars().all()) == 0
            assert len((await db.execute(select(DSLeakRecord))).scalars().all()) == 0
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.parametrize(
    ("pattern_name", "positive", "negative"),
    [
        ("aws_access_key_id", "AKIA1234567890ABCDEF", "AKI1234567890ABCDEF"),
        ("aws_secret_access_key", "aws secret = 'A' * 40", "aws secret = short"),
        ("github_pat", "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL123456", "ghp_short"),
        ("slack_token", "xoxb-1234567890-1234567890", "xox-123"),
        ("google_api_key", "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AIza-short"),
        ("private_key_pem", "-----BEGIN PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----"),
        ("jwt", "eyJabcdefghij.eyJabcdefghij.abcdefghijk", "eyJshort.jwt"),
        ("generic_password_assign", "password = \"hunter22\"", "password = short"),
        ("email_address", "alice@example.com", "alice_at_example.com"),
        ("us_ssn", "123-45-6789", "000-00-0000"),
        ("credit_card", "4111 1111 1111 1111", "1234 5678 9012 3456"),
    ],
)
def test_pattern_registry_positive_and_negative_cases(pattern_name, positive, negative):
    content = positive.replace("'A' * 40", "A" * 40)
    matches = [match for match in scan_chunk(content, chunk_id=1, file_id=1) if match.pattern_name == pattern_name]
    assert len(matches) == 1
    masked = matches[0].matched_value_masked
    raw = matches[0].matched_value
    assert len(masked) == len(raw)
    assert masked[:2] == raw[:2]
    assert masked[-2:] == raw[-2:]
    assert any(char == "*" for char in masked[2:-2]) or len(raw) <= 4
    assert [match for match in scan_chunk(negative, chunk_id=1, file_id=1) if match.pattern_name == pattern_name] == []


def test_pattern_registry_includes_all_expected_patterns():
    assert len(PATTERN_REGISTRY) == 11


def test_manual_trigger_endpoint_rbac_and_status_codes(monkeypatch):
    async def run_case(user_role: str, ds_enabled: bool | None, source_id: int):
        engine, session_factory, db_path = await _build_session()
        try:
            async with session_factory() as db:
                user = User(username=f"user-{user_role}", password_hash="hash", role=user_role)
                db.add(user)
                await db.flush()
                if ds_enabled is not None:
                    db.add(
                        DSStorageSource(
                            id=source_id,
                            display_name="Router Source",
                            source_type="localfs",
                            enabled=ds_enabled,
                            credentials={},
                        )
                    )
                await db.commit()
                await db.refresh(user)

            queued = []
            monkeypatch.setattr(deep_search_tasks, "enqueue_ingest_source", lambda *args, **kwargs: queued.append((args, kwargs)))

            app = FastAPI()
            app.include_router(storage_sources_router, prefix="/api/v1/storage-sources")

            async def override_get_db():
                async with session_factory() as db:
                    yield db

            app.dependency_overrides[get_db] = override_get_db
            app.dependency_overrides[get_current_user] = lambda: user

            with TestClient(app) as client:
                response = client.post(f"/api/v1/storage-sources/{source_id}/deep-ingest")
            return response, queued
        finally:
            await engine.dispose()
            os.remove(db_path)

    response, queued = asyncio.run(run_case("analyst", True, 1))
    assert response.status_code == 403
    assert queued == []

    response, queued = asyncio.run(run_case("admin", True, 2))
    assert response.status_code == 200
    assert response.json() == {"ok": True, "queued": True, "source_id": 2}
    assert len(queued) == 1

    response, _ = asyncio.run(run_case("admin", None, 3))
    assert response.status_code == 404

    response, _ = asyncio.run(run_case("admin", False, 4))
    assert response.status_code == 400


def test_scheduler_parallel_run_invokes_legacy_and_deep_ingestion(monkeypatch):
    async def run_case():
        from app import database
        from app.services import scheduler, storage_indexer

        engine, session_factory, db_path = await _build_session()
        try:
            async with session_factory() as db:
                source = StorageSource(
                    name="Scheduled Source",
                    source_type="localfs",
                    config_encrypted=_encrypt_config({"base_path": "/tmp"}),
                    is_enabled=True,
                    schedule="@hourly",
                    recursive=True,
                )
                db.add(source)
                await db.flush()
                db.add(
                    DSStorageSource(
                        id=source.id,
                        display_name=source.name,
                        source_type=source.source_type,
                        enabled=True,
                        credentials={},
                    )
                )
                await db.commit()

            jobs = {}
            monkeypatch.setattr(database, "AsyncSessionLocal", session_factory)
            monkeypatch.setattr(
                scheduler._scheduler,
                "add_job",
                lambda func, *args, **kwargs: jobs.setdefault(kwargs.get("id"), func),
            )
            monkeypatch.setattr(scheduler._scheduler, "start", lambda: None)

            legacy_calls = []
            deep_calls = []

            async def fake_run_source_indexing(source_id: int):
                legacy_calls.append(source_id)
                return {"status": "ok"}

            monkeypatch.setattr(storage_indexer, "run_source_indexing", fake_run_source_indexing)
            monkeypatch.setattr(deep_search_tasks, "enqueue_ingest_source", lambda source_id, **kwargs: deep_calls.append((source_id, kwargs)))

            scheduler.start_scheduler()
            await jobs["scan_storage_sources"]()

            assert legacy_calls == [1]
            assert deep_calls == [(1, {"triggered_by": "scheduler"})]
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(run_case())


@pytest.mark.asyncio
async def test_audit_event_payloads_emit_leak_detected_once_per_file(tmp_path, monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    (tmp_path / "multi.txt").write_text(
        "AKIA1234567890ABCDEF\nadmin@example.com\nother@example.com\n",
        encoding="utf-8",
    )

    engine, session_factory, db_path = await _build_session()
    monkeypatch.setattr(deep_search_ingestion, "AsyncSessionLocal", session_factory)
    try:
        source_id = await _create_source_pair(session_factory, {"base_path": str(tmp_path)})
        await deep_search_ingestion.ingest_source(source_id, triggered_by="test")

        async with session_factory() as db:
            audits = list(
                (await db.execute(select(AuditLogEntry).where(AuditLogEntry.action == DeepSearchAuditEvent.LEAK_DETECTED.value))).scalars().all()
            )
        assert len(audits) == 1
        payload = json.loads(audits[0].new_value_json)
        assert payload["leak_count"] == 3
        assert payload["severity_max"] == 95
        assert sorted(payload["pattern_names"]) == ["aws_access_key_id", "email_address"]
    finally:
        await engine.dispose()
        os.remove(db_path)
