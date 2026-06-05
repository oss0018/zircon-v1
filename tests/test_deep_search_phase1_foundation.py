import os
import json
import tempfile
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import storage_sources as storage_sources_api
from app.api.storage_sources import create_storage_source, update_storage_source, _decrypt_config_payload
from app.database import Base, _migrate_ds_source_credentials
from app.models import DSChunk, DSFile, DSLeakRecord, DSMonitoredEntity, DSStorageSource, StorageSource, User
from app.schemas import StorageSourceCreate, StorageSourceUpdate
from app.services import storage_indexer
from app.services.crypto import encrypt
from app.services.deep_search_audit import DeepSearchAuditEvent
from app.services.deep_search_rbac import require_role
from app.services.security import PathTraversalError, sanitise_path
from app.services.storage_credential_vault import StorageCredentialVault

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


def _parse_db_json(value):
    if isinstance(value, str):
        return json.loads(value)
    return value or {}


def test_vault_round_trip_encrypt_decrypt(monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    vault = StorageCredentialVault()
    creds = {"username": "alice", "password": "s3cr3t", "api_token": "tok", "region": "eu-west-1"}

    encrypted = vault.encrypt_credentials(creds)
    assert encrypted["password"].startswith("gcm:")
    assert encrypted["api_token"].startswith("gcm:")
    assert encrypted["username"] == "alice"
    assert encrypted["region"] == "eu-west-1"

    decrypted = vault.decrypt_credentials(encrypted)
    assert decrypted == creds


def test_vault_does_not_double_encrypt(monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    vault = StorageCredentialVault()
    once = vault.encrypt_credentials({"password": "secret"})
    twice = vault.encrypt_credentials(once)
    assert twice["password"] == once["password"]


def test_vault_wrong_kek_raises_clear_error():
    vault_a = StorageCredentialVault(kek_b64=TEST_KEK_A)
    vault_b = StorageCredentialVault(kek_b64=TEST_KEK_B)
    encrypted = vault_a.encrypt_credentials({"password": "topsecret"})
    with pytest.raises(ValueError, match="invalid KEK or ciphertext"):
        vault_b.decrypt_credentials(encrypted)


def test_sanitise_path_blocks_traversal(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(PathTraversalError):
        sanitise_path("../etc/passwd", str(base))


def test_sanitise_path_blocks_absolute_path(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(PathTraversalError):
        sanitise_path(str(outside), str(base))


def test_sanitise_path_blocks_symlink_escape(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "link"
    os.symlink(outside, link)
    with pytest.raises(PathTraversalError):
        sanitise_path("link/secret.txt", str(base))


def test_sanitise_path_allows_legitimate_path(tmp_path):
    base = tmp_path / "base"
    nested = base / "nested"
    nested.mkdir(parents=True)
    good = nested / "ok.txt"
    good.write_text("ok", encoding="utf-8")
    assert sanitise_path("nested/ok.txt", str(base)) == str(good.resolve())


def test_deep_search_schema_models_have_required_indexes():
    ds_files_indexes = {idx.name for idx in DSFile.__table__.indexes}
    assert {"idx_ds_files_source", "idx_ds_files_status", "idx_ds_files_severity", "idx_ds_files_path"}.issubset(
        ds_files_indexes
    )
    ds_chunks_indexes = {idx.name for idx in DSChunk.__table__.indexes}
    assert {"idx_ds_chunks_file", "idx_ds_chunks_fts"}.issubset(ds_chunks_indexes)
    ds_leak_indexes = {idx.name for idx in DSLeakRecord.__table__.indexes}
    assert {
        "idx_ds_leak_file",
        "idx_ds_leak_category",
        "idx_ds_leak_severity",
        "idx_ds_leak_email",
        "idx_ds_leak_domain",
        "idx_ds_leak_pattern",
    }.issubset(ds_leak_indexes)


def test_deep_search_schema_models_have_required_uniques():
    file_uniques = {c.name for c in DSFile.__table__.constraints}
    monitored_uniques = {c.name for c in DSMonitoredEntity.__table__.constraints}
    assert "uq_ds_files_source_path" in file_uniques
    assert "uq_ds_monitored_entities_type_value" in monitored_uniques


@pytest.mark.asyncio
async def test_deep_search_rbac_require_role_accepts_and_rejects():
    dependency = require_role("sec_engineer", "admin")
    allowed_user = type("U", (), {"role": "admin"})()
    denied_user = type("U", (), {"role": "analyst"})()
    assert await dependency(allowed_user) is allowed_user
    with pytest.raises(HTTPException):
        await dependency(denied_user)


def test_deep_search_audit_event_values_are_canonical():
    assert DeepSearchAuditEvent.SOURCE_CREATE.value == "source.create"
    assert DeepSearchAuditEvent.SOURCE_DELETE.value == "source.delete"
    assert DeepSearchAuditEvent.SOURCE_CREDENTIALS_EDIT.value == "source.credentials_edit"


def test_ds_storage_source_model_includes_credentials_column():
    columns = {c.key for c in DSStorageSource.__table__.columns}
    assert "credentials" in columns


@pytest.mark.asyncio
async def test_storage_source_sync_does_not_store_plaintext_credentials_and_preserves_creator(monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    monkeypatch.setattr(storage_sources_api, "_vault", None)
    engine, session_factory, db_path = await _build_session()
    try:
        async with session_factory() as db:
            user_a = User(username="alice", password_hash="hash", role="admin")
            user_b = User(username="bob", password_hash="hash", role="admin")
            db.add_all([user_a, user_b])
            await db.commit()
            await db.refresh(user_a)
            await db.refresh(user_b)

            source = await create_storage_source(
                StorageSourceCreate(
                    name="Source A",
                    source_type="sftp",
                    config={"username": "alice", "password": "topsecret", "host": "example.test"},
                ),
                db,
                user_a,
            )
            row = (
                await db.execute(
                    text("SELECT credentials, created_by FROM ds_sources WHERE id = :id"),
                    {"id": source.id},
                )
            ).one()
            assert _parse_db_json(row.credentials) == {}
            assert row.created_by == user_a.id

            updated = await update_storage_source(
                source.id,
                StorageSourceUpdate(name="Source B", config={"username": "bob", "password": "***"}),
                db,
                user_b,
            )
            updated_row = (
                await db.execute(
                    text("SELECT credentials, created_by FROM ds_sources WHERE id = :id"),
                    {"id": updated.id},
                )
            ).one()
            assert _parse_db_json(updated_row.credentials) == {}
            assert updated_row.created_by == user_a.id

            stored_source = (
                await db.execute(select(StorageSource).where(StorageSource.id == source.id))
            ).scalar_one()
            assert _decrypt_config_payload(stored_source.config_encrypted)["password"] == "topsecret"
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_run_source_indexing_fails_fast_on_vault_decrypt_error(monkeypatch, caplog):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_B)
    engine, session_factory, db_path = await _build_session()
    connector_mock = Mock(side_effect=AssertionError("connector should not be created"))
    monkeypatch.setattr(storage_indexer, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(storage_indexer, "get_connector", connector_mock)
    try:
        async with session_factory() as db:
            encrypted_config = encrypt(
                json.dumps(StorageCredentialVault(kek_b64=TEST_KEK_A).encrypt_credentials({"password": "topsecret"}))
            )
            source = StorageSource(
                name="Broken Source",
                source_type="localfs",
                config_encrypted=encrypted_config,
                is_enabled=True,
            )
            db.add(source)
            await db.commit()
            await db.refresh(source)

        summary = await storage_indexer.run_source_indexing(source.id)
        assert summary["status"] == "error"
        assert summary["errors"] == 1
        connector_mock.assert_not_called()
        assert "DS_CREDENTIAL_KEK" in caplog.text

        async with session_factory() as db:
            stored = (await db.execute(select(StorageSource).where(StorageSource.id == source.id))).scalar_one()
            assert stored.last_run_status == "error"
            assert stored.last_run_error_msg == "credential vault decryption failed — check DS_CREDENTIAL_KEK"
    finally:
        await engine.dispose()
        os.remove(db_path)


def test_migrate_ds_source_credentials_encrypts_plaintext_and_is_idempotent(monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", TEST_KEK_A)
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO ds_sources (id, display_name, source_type, credentials) "
                "VALUES (:id, :display_name, :source_type, :credentials)"
            ),
            {
                "id": 1,
                "display_name": "Migrated Source",
                "source_type": "sftp",
                "credentials": json.dumps({"username": "alice", "password": "topsecret"}),
            },
        )
        _migrate_ds_source_credentials(conn)
        migrated = _parse_db_json(
            conn.execute(text("SELECT credentials FROM ds_sources WHERE id = 1")).scalar_one()
        )
        assert migrated["password"].startswith("gcm:")
        assert migrated["username"] == "alice"

        _migrate_ds_source_credentials(conn)
        migrated_again = _parse_db_json(
            conn.execute(text("SELECT credentials FROM ds_sources WHERE id = 1")).scalar_one()
        )
        assert migrated_again == migrated
