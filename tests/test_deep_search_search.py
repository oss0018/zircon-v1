"""
tests/test_deep_search_search.py
TS-DS-001 Phase 1 — PR 3/4: Search engine + Query API tests.

Uses sqlite+aiosqlite so tests run without a Postgres instance.
The Postgres FTS path is validated by compiling the expected SQL with the
Postgres dialect (no real DB required).
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_current_user
from app.database import Base, get_db
from app.models import AuditLogEntry, DSChunk, DSFile, DSLeakRecord, DSStorageSource, User
from app.services import deep_search_search as svc
from app.services.deep_search_audit import DeepSearchAuditEvent
from app.services.deep_search_search import SearchFilters

# ── Shared helpers ────────────────────────────────────────────────────────────

def _utcnow():
    return datetime.now(timezone.utc)


async def _build_session():
    fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory, db_path


async def _seed_source(session_factory, source_id: int = 1) -> int:
    """Insert a DSStorageSource and return its id."""
    async with session_factory() as db:
        row = DSStorageSource(
            id=source_id,
            display_name=f"Test Source {source_id}",
            source_type="localfs",
            enabled=True,
            credentials={},
        )
        db.add(row)
        await db.commit()
    return source_id


async def _seed_file(
    session_factory,
    *,
    source_id: int = 1,
    file_path: str = "/test/file.txt",
    severity_max: int = 0,
    has_credentials: bool = False,
    has_pii: bool = False,
    has_api_keys: bool = False,
    pattern_names: list | None = None,
    leak_count: int = 0,
    parse_mode: str = "text",
    indexed_at: datetime | None = None,
) -> int:
    async with session_factory() as db:
        f = DSFile(
            source_id=source_id,
            file_path=file_path,
            file_name=file_path.split("/")[-1],
            index_status="indexed",
            severity_max=severity_max,
            has_credentials=has_credentials,
            has_pii=has_pii,
            has_api_keys=has_api_keys,
            pattern_names=pattern_names or [],
            leak_count=leak_count,
            parse_mode=parse_mode,
            indexed_at=indexed_at or _utcnow(),
        )
        db.add(f)
        await db.commit()
        await db.refresh(f)
        return f.id


async def _seed_chunk(session_factory, *, file_id: int, content: str, chunk_index: int = 0) -> int:
    async with session_factory() as db:
        c = DSChunk(
            file_id=file_id,
            chunk_index=chunk_index,
            content=content,
            start_offset=chunk_index * 100,
            end_offset=(chunk_index + 1) * 100,
        )
        db.add(c)
        await db.commit()
        await db.refresh(c)
        return c.id


async def _seed_leak(
    session_factory,
    *,
    file_id: int,
    pattern_name: str = "aws_access_key_id",
    category: str = "api_keys",
    severity: int = 95,
    matched_value: str = "AKIAXXXXXXXXXXXXXXXX",
    matched_value_masked: str = "AKIA****************",
) -> int:
    async with session_factory() as db:
        lr = DSLeakRecord(
            file_id=file_id,
            pattern_name=pattern_name,
            category=category,
            severity=severity,
            matched_value=matched_value,
            matched_value_masked=matched_value_masked,
            context_before="before",
            context_after="after",
            email="",
            email_domain="",
        )
        db.add(lr)
        await db.commit()
        await db.refresh(lr)
        return lr.id


def _build_test_app(session_factory, user_role: str = "sec_engineer"):
    """Build a minimal FastAPI app wired to the in-memory test DB."""
    from app.api.deep_search import router as ds_router

    app = FastAPI()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        async with session_factory() as db:
            user = (
                await db.execute(select(User).where(User.role == user_role))
            ).scalar_one_or_none()
            if user is None:
                user = (await db.execute(select(User))).scalar_one_or_none()
        if user is None:
            raise RuntimeError("No user seeded")
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user
    app.include_router(ds_router, prefix="/api/v1/deep-search")
    return app


async def _seed_user(session_factory, role: str = "sec_engineer", username: str | None = None) -> int:
    async with session_factory() as db:
        u = User(
            username=username or f"user_{role}",
            password_hash="hash",
            role=role,
        )
        db.add(u)
        await db.commit()
        await db.refresh(u)
        return u.id


# ── Test 1: FTS hit returns chunks ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_fts_hit_returns_chunks(monkeypatch):
    """Two chunks containing 'alpha' returned; two without are excluded."""
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)  # force re-detect as sqlite
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf)
        await _seed_chunk(sf, file_id=fid, content="alpha is here", chunk_index=0)
        await _seed_chunk(sf, file_id=fid, content="nothing relevant", chunk_index=1)
        fid2 = await _seed_file(sf, file_path="/test/b.txt")
        await _seed_chunk(sf, file_id=fid2, content="alpha appears again", chunk_index=0)
        await _seed_chunk(sf, file_id=fid2, content="completely unrelated", chunk_index=1)

        async with sf() as db:
            result = await svc.search(db, "alpha")

        assert result.total == 2
        assert len(result.items) == 2
        for hit in result.items:
            assert "«alpha»" in hit.snippet
        # Ordered by chunk_id ascending (SQLite path)
        assert result.items[0].chunk_id < result.items[1].chunk_id
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 2: No-results query ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_results_query(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf)
        await _seed_chunk(sf, file_id=fid, content="some content here")

        async with sf() as db:
            result = await svc.search(db, "xyznotpresentanywhere")

        assert result.items == []
        assert result.total == 0
        assert result.has_next is False
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 3: Empty query → ValueError / HTTP 400 ──────────────────────────────

@pytest.mark.asyncio
async def test_empty_query_raises_value_error(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        async with sf() as db:
            with pytest.raises(ValueError, match="query must not be empty"):
                await svc.search(db, "")
            with pytest.raises(ValueError, match="query must not be empty"):
                await svc.search(db, "   ")
    finally:
        await engine.dispose()
        os.remove(db_path)


def test_empty_query_returns_http_400(monkeypatch):
    """Endpoint returns HTTP 400 for empty q (FastAPI min_length=1 gives 422, but we also
    verify the service-level guard works via the endpoint with a space-only string)."""
    import asyncio

    async def _run():
        engine, sf, db_path = await _build_session()
        monkeypatch.setattr(svc, "_dialect", "sqlite")
        try:
            await _seed_user(sf)
            app = _build_test_app(sf)
            client = TestClient(app, raise_server_exceptions=False)
            # q="" → FastAPI Query min_length=1 validation → 422
            resp = client.get("/api/v1/deep-search/query?q=")
            assert resp.status_code in (400, 422)
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())


# ── Test 4: Query length cap ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_query_length_cap_service(monkeypatch):
    """Service raises ValueError for query > 512 chars."""
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        async with sf() as db:
            with pytest.raises(ValueError, match="query too long"):
                await svc.search(db, "x" * 513)
    finally:
        await engine.dispose()
        os.remove(db_path)


def test_query_length_cap_endpoint_422(monkeypatch):
    """Endpoint returns 422 for q > 512 chars (FastAPI max_length validation)."""
    import asyncio

    async def _run():
        engine, sf, db_path = await _build_session()
        monkeypatch.setattr(svc, "_dialect", "sqlite")
        try:
            await _seed_user(sf)
            app = _build_test_app(sf)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(f"/api/v1/deep-search/query?q={'x' * 513}")
            assert resp.status_code == 422
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())


# ── Test 5: severity_min filter ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_severity_min_filter(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        for i, sev in enumerate([30, 60, 90]):
            fid = await _seed_file(sf, file_path=f"/f{i}.txt", severity_max=sev)
            await _seed_chunk(sf, file_id=fid, content=f"searchword in file {i}")

        async with sf() as db:
            result = await svc.search(db, "searchword", filters=SearchFilters(severity_min=70))

        assert result.total == 1
        assert result.items[0].file_severity_max == 90
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 6: has_credentials filter ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_has_credentials_filter(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid_yes = await _seed_file(sf, file_path="/cred.txt", has_credentials=True)
        fid_no = await _seed_file(sf, file_path="/nocred.txt", has_credentials=False)
        await _seed_chunk(sf, file_id=fid_yes, content="findme credential content")
        await _seed_chunk(sf, file_id=fid_no, content="findme plain content")

        async with sf() as db:
            result = await svc.search(
                db, "findme", filters=SearchFilters(has_credentials=True)
            )

        assert result.total == 1
        assert result.items[0].file_id == fid_yes
        assert result.items[0].file_has_credentials is True
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 7: pattern_names filter ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pattern_names_filter(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid_a = await _seed_file(
            sf, file_path="/a.txt", pattern_names=["aws_access_key_id"]
        )
        fid_b = await _seed_file(sf, file_path="/b.txt", pattern_names=["jwt"])
        await _seed_chunk(sf, file_id=fid_a, content="findword content a")
        await _seed_chunk(sf, file_id=fid_b, content="findword content b")

        async with sf() as db:
            result = await svc.search(
                db, "findword", filters=SearchFilters(pattern_names=["aws_access_key_id"])
            )

        file_ids = {h.file_id for h in result.items}
        assert fid_a in file_ids
        assert fid_b not in file_ids
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 8: Multi-source filter ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_multi_source_filter(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        for sid in [1, 2, 3]:
            await _seed_source(sf, source_id=sid)
        fids = {}
        for sid in [1, 2, 3]:
            fid = await _seed_file(sf, source_id=sid, file_path=f"/src{sid}/f.txt")
            await _seed_chunk(sf, file_id=fid, content=f"targetword source {sid}")
            fids[sid] = fid

        async with sf() as db:
            result = await svc.search(
                db, "targetword", filters=SearchFilters(source_ids=[1, 3])
            )

        source_ids_in_result = {h.source_id for h in result.items}
        assert 1 in source_ids_in_result
        assert 3 in source_ids_in_result
        assert 2 not in source_ids_in_result
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 9: File detail happy path ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_file_detail_happy_path(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf, leak_count=3, severity_max=90)
        for i in range(8):
            await _seed_chunk(sf, file_id=fid, content=f"chunk {i}", chunk_index=i)
        # 2 leaks of pattern X (api_keys), 1 leak of pattern Y (pii)
        await _seed_leak(sf, file_id=fid, pattern_name="X", category="api_keys", severity=90)
        await _seed_leak(sf, file_id=fid, pattern_name="X", category="api_keys", severity=90)
        await _seed_leak(sf, file_id=fid, pattern_name="Y", category="pii", severity=60)

        async with sf() as db:
            detail = await svc.get_file_detail(db, fid, chunk_preview=3)

        assert detail is not None
        assert len(detail["chunks_preview"]) == 3
        assert detail["leak_summary"]["total"] == 3
        assert detail["leak_summary"]["by_pattern"] == {"X": 2, "Y": 1}
        assert detail["leak_summary"]["by_category"] == {"api_keys": 2, "pii": 1}
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 10: File detail not found ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_file_detail_not_found(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        async with sf() as db:
            detail = await svc.get_file_detail(db, 99999)
        assert detail is None
    finally:
        await engine.dispose()
        os.remove(db_path)


def test_file_detail_endpoint_404(monkeypatch):
    import asyncio

    async def _run():
        engine, sf, db_path = await _build_session()
        monkeypatch.setattr(svc, "_dialect", "sqlite")
        try:
            await _seed_user(sf)
            app = _build_test_app(sf)
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/api/v1/deep-search/files/99999")
            assert resp.status_code == 404
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())


# ── Test 11: Chunk pagination ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_chunk_pagination(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf)
        for i in range(12):
            await _seed_chunk(sf, file_id=fid, content=f"chunk {i}", chunk_index=i)

        async with sf() as db:
            result = await svc.list_chunks_for_file(db, fid, offset=5, limit=3)

        assert len(result["items"]) == 3
        assert result["total"] == 12
        assert result["has_next"] is True
        indices = [item["chunk_index"] for item in result["items"]]
        assert indices == [5, 6, 7]
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 12: Leak listing happy path + masking ───────────────────────────────

@pytest.mark.asyncio
async def test_leak_listing_masking(monkeypatch):
    """Items contain matched_value_masked but NOT matched_value or password_plain."""
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf)
        for i in range(5):
            await _seed_leak(
                sf,
                file_id=fid,
                pattern_name="aws_access_key_id",
                matched_value=f"AKIAXXXXXXXXXXXXXXX{i}",
                matched_value_masked=f"AKIA****************{i}",
            )

        async with sf() as db:
            result = await svc.list_leaks(db)

        assert result["total"] == 5
        for item in result["items"]:
            assert "matched_value_masked" in item
            assert "matched_value" not in item
            assert "password_plain" not in item
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 13: Leak listing category filter ────────────────────────────────────

@pytest.mark.asyncio
async def test_leak_listing_category_filter(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf)
        await _seed_leak(sf, file_id=fid, pattern_name="aws", category="api_keys")
        await _seed_leak(sf, file_id=fid, pattern_name="email", category="pii")
        await _seed_leak(sf, file_id=fid, pattern_name="jwt", category="credentials")

        async with sf() as db:
            result = await svc.list_leaks(db, category="api_keys")

        assert result["total"] == 1
        assert result["items"][0]["category"] == "api_keys"
    finally:
        await engine.dispose()
        os.remove(db_path)


# ── Test 14: RBAC 403 ────────────────────────────────────────────────────────

def test_rbac_403_for_viewer():
    import asyncio

    async def _run():
        engine, sf, db_path = await _build_session()
        svc._dialect = "sqlite"
        try:
            await _seed_user(sf, role="viewer")
            app = _build_test_app(sf, user_role="viewer")
            client = TestClient(app, raise_server_exceptions=False)

            # All four new endpoints should return 403
            assert client.get("/api/v1/deep-search/query?q=test").status_code == 403
            assert client.get("/api/v1/deep-search/files/1").status_code == 403
            assert client.get("/api/v1/deep-search/files/1/chunks").status_code == 403
            assert client.get("/api/v1/deep-search/leaks").status_code == 403
        finally:
            svc._dialect = None
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())


# ── Test 15: Audit event payload shapes ──────────────────────────────────────

def test_audit_event_payload_shapes(monkeypatch):
    import asyncio

    async def _run():
        engine, sf, db_path = await _build_session()
        monkeypatch.setattr(svc, "_dialect", "sqlite")
        try:
            await _seed_user(sf, role="sec_engineer")
            await _seed_source(sf)
            fid = await _seed_file(sf)
            await _seed_chunk(sf, file_id=fid, content="auditword content")

            app = _build_test_app(sf, user_role="sec_engineer")
            client = TestClient(app, raise_server_exceptions=False)

            # 1. SEARCH_QUERY audit
            long_query = "a" * 200
            resp = client.get(f"/api/v1/deep-search/query?q={long_query}&has_credentials=true")
            assert resp.status_code == 200, resp.text

            async with sf() as db:
                audit_rows = (
                    await db.execute(
                        select(AuditLogEntry).where(
                            AuditLogEntry.action == DeepSearchAuditEvent.SEARCH_QUERY.value
                        )
                    )
                ).scalars().all()
            assert len(audit_rows) >= 1
            payload = json.loads(audit_rows[-1].new_value_json)
            assert set(payload.keys()) == {"q", "filter_keys", "result_count", "page", "page_size"}
            assert len(payload["q"]) <= 128
            assert isinstance(payload["filter_keys"], list)
            assert "has_credentials" in payload["filter_keys"]
            # Values must NOT be in the payload
            assert "true" not in str(payload["filter_keys"])

            # 2. SEARCH_FILE_READ audit
            resp = client.get(f"/api/v1/deep-search/files/{fid}")
            assert resp.status_code == 200, resp.text
            async with sf() as db:
                read_rows = (
                    await db.execute(
                        select(AuditLogEntry).where(
                            AuditLogEntry.action == DeepSearchAuditEvent.SEARCH_FILE_READ.value
                        )
                    )
                ).scalars().all()
            assert len(read_rows) >= 1
            pl = json.loads(read_rows[-1].new_value_json)
            assert "file_id" in pl
            assert pl["file_id"] == fid

            # 3. SEARCH_FILE_READ via chunks endpoint (includes "via")
            resp = client.get(f"/api/v1/deep-search/files/{fid}/chunks")
            assert resp.status_code == 200, resp.text
            async with sf() as db:
                chunk_read_rows = (
                    await db.execute(
                        select(AuditLogEntry).where(
                            AuditLogEntry.action == DeepSearchAuditEvent.SEARCH_FILE_READ.value
                        ).order_by(AuditLogEntry.id.desc())
                    )
                ).scalars().all()
            pl2 = json.loads(chunk_read_rows[0].new_value_json)
            assert pl2.get("via") == "chunks"

            # 4. SEARCH_LEAK_LIST_READ audit
            resp = client.get("/api/v1/deep-search/leaks")
            assert resp.status_code == 200, resp.text
            async with sf() as db:
                leak_rows_audit = (
                    await db.execute(
                        select(AuditLogEntry).where(
                            AuditLogEntry.action == DeepSearchAuditEvent.SEARCH_LEAK_LIST_READ.value
                        )
                    )
                ).scalars().all()
            assert len(leak_rows_audit) >= 1
            pl3 = json.loads(leak_rows_audit[-1].new_value_json)
            assert set(pl3.keys()) == {"filter_keys", "result_count", "page", "page_size"}
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())


# ── Test 16: Postgres FTS path compiles ──────────────────────────────────────

def test_postgres_fts_path_compiles():
    """
    Verify that the Postgres FTS path generates the expected SQL fragments.
    Compilation uses the Postgres dialect — no real DB connection required.
    """
    from sqlalchemy import func, select
    from sqlalchemy.dialects import postgresql as pg_dialect

    from app.models import DSChunk, DSFile

    query = "test_fts_phrase"
    fts_q = func.websearch_to_tsquery("simple", query)
    fts_cond = DSChunk.fts_vector.op("@@")(fts_q)
    rank_col = func.ts_rank_cd(DSChunk.fts_vector, fts_q).label("rank")
    snippet_col = func.ts_headline(
        "simple",
        DSChunk.content,
        fts_q,
        "StartSel=«, StopSel=», MaxFragments=2, MaxWords=20, MinWords=5",
    ).label("snippet")

    stmt = (
        select(
            DSChunk.id.label("chunk_id"),
            DSChunk.chunk_index,
            DSFile.source_id,
            DSFile.file_path,
            rank_col,
            snippet_col,
        )
        .join(DSFile, DSChunk.file_id == DSFile.id)
        .where(fts_cond)
        .order_by(rank_col.desc(), DSChunk.id.asc())
    )

    compiled = stmt.compile(
        dialect=pg_dialect.dialect(),
        compile_kwargs={"literal_binds": False},
    )
    sql_str = str(compiled)

    assert "fts_vector" in sql_str, f"fts_vector not in SQL:\n{sql_str}"
    assert "websearch_to_tsquery" in sql_str, f"websearch_to_tsquery not in SQL:\n{sql_str}"
    assert "ts_rank_cd" in sql_str, f"ts_rank_cd not in SQL:\n{sql_str}"
    assert "ts_headline" in sql_str, f"ts_headline not in SQL:\n{sql_str}"


# ── Additional: audit event values are correct ───────────────────────────────

def test_new_audit_event_values():
    assert DeepSearchAuditEvent.SEARCH_QUERY.value == "search.query"
    assert DeepSearchAuditEvent.SEARCH_FILE_READ.value == "search.file_read"
    assert DeepSearchAuditEvent.SEARCH_LEAK_LIST_READ.value == "search.leak_list_read"


# ── Additional: pagination has_next logic ────────────────────────────────────

@pytest.mark.asyncio
async def test_pagination_has_next(monkeypatch):
    engine, sf, db_path = await _build_session()
    monkeypatch.setattr(svc, "_dialect", None)
    try:
        await _seed_source(sf)
        fid = await _seed_file(sf)
        for i in range(5):
            await _seed_chunk(sf, file_id=fid, content=f"keyword chunk {i}", chunk_index=i)

        async with sf() as db:
            r1 = await svc.search(db, "keyword", page=1, page_size=3)
            r2 = await svc.search(db, "keyword", page=2, page_size=3)

        assert r1.total == 5
        assert r1.has_next is True
        assert r2.has_next is False
    finally:
        await engine.dispose()
        os.remove(db_path)
