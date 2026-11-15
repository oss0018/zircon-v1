import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_current_user
from app.database import _migrate_nazk_watch_documents, _migrate_nazk_watches, get_db
from app.main import app
from app.models import NazkWatch, NazkWatchDocument, Notification, User
from app.services.nazk import NazkSourceError
from app.services.nazk_monitoring import _snapshot, run_due_watches, run_watch


def test_baseline_new_documents_and_failure_are_atomic(monkeypatch):
    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync: User.__table__.create(sync))
            await conn.run_sync(lambda sync: Notification.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatch.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatchDocument.__table__.create(sync))
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as db:
            watch = NazkWatch(owner_id=1, declarant_id=123, label="Person")
            db.add(watch)
            await db.commit()
            state = {"ids": {"a", "b"}, "fail": False}

            async def snapshot(_watch):
                if state["fail"]:
                    raise NazkSourceError("source unavailable")
                return state["ids"]

            monkeypatch.setattr("app.services.nazk_monitoring._snapshot", snapshot)
            assert await run_watch(db, watch.id)
            assert watch.baseline_complete and watch.last_status == "success"
            assert not (await db.execute(select(Notification))).scalars().all()
            assert not (await db.execute(select(NazkWatchDocument).where(
                NazkWatchDocument.discovered_after_baseline.is_(True)))).scalars().all()
            assert not await run_watch(db, watch.id)
            watch.last_attempt = datetime.now(timezone.utc) - timedelta(days=2)
            state["ids"] = {"b", "c"}
            await db.commit()
            assert await run_watch(db, watch.id)
            assert set((await db.execute(select(NazkWatchDocument.document_id))).scalars()) == {"a", "b", "c"}
            assert len((await db.execute(select(Notification))).scalars().all()) == 1
            assert list((await db.execute(select(NazkWatchDocument.document_id).where(
                NazkWatchDocument.discovered_after_baseline.is_(True)))).scalars()) == ["c"]
            watch.last_attempt = datetime.now(timezone.utc) - timedelta(days=2)
            state["fail"] = True
            await db.commit()
            assert await run_watch(db, watch.id)
            await db.refresh(watch)
            assert watch.last_status == "failed"
            assert watch.last_error == "source unavailable"
            assert set((await db.execute(select(NazkWatchDocument.document_id))).scalars()) == {"a", "b", "c"}
            assert len((await db.execute(select(Notification))).scalars().all()) == 1
            watch.last_status = "running"
            watch.lease_until = datetime.now(timezone.utc) - timedelta(minutes=1)
            watch.last_attempt = datetime.now(timezone.utc)
            await db.commit()
            await run_due_watches(db)
            await db.refresh(watch)
            assert watch.last_status == "failed"
            assert watch.last_error == "NACP check was interrupted"
        await engine.dispose()
    asyncio.run(exercise())


def test_snapshot_rejects_incomplete_oversized_and_wrong_identity(monkeypatch):
    async def exercise():
        watch = NazkWatch(declarant_id=123, label="Person")
        state = {"result": {"count": 1, "results": []}}

        async def search(*_args):
            return state["result"]

        monkeypatch.setattr("app.services.nazk_monitoring.search_declarations", search)
        for result in (
            {"count": 1, "results": []},
            {"count": 10001, "results": []},
            {"count": 1, "results": [{"id": "a", "declarant_id": 456}]},
        ):
            state["result"] = result
            try:
                await _snapshot(watch)
            except NazkSourceError:
                pass
            else:
                raise AssertionError("Incomplete or unsafe snapshot accepted")
    asyncio.run(exercise())


def test_existing_watch_documents_are_migrated_without_marking_baseline_as_new():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE nazk_watch_documents (id INTEGER PRIMARY KEY)")
        conn.exec_driver_sql("INSERT INTO nazk_watch_documents (id) VALUES (1)")
        _migrate_nazk_watch_documents(conn)
        _migrate_nazk_watch_documents(conn)
        assert conn.exec_driver_sql(
            "SELECT discovered_after_baseline FROM nazk_watch_documents"
        ).scalar_one() == 0
    engine.dispose()


def test_existing_watches_get_lease_token_column():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE nazk_watches (id INTEGER PRIMARY KEY)")
        conn.exec_driver_sql("INSERT INTO nazk_watches (id) VALUES (1)")
        _migrate_nazk_watches(conn)
        _migrate_nazk_watches(conn)
        assert conn.exec_driver_sql("SELECT lease_token FROM nazk_watches").scalar_one() is None
    engine.dispose()


@pytest.mark.parametrize("failure", [False, True])
def test_deleted_and_recreated_watch_cannot_be_updated_by_old_check(monkeypatch, tmp_path, failure):
    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "race.db"))
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync: User.__table__.create(sync))
            await conn.run_sync(lambda sync: Notification.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatch.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatchDocument.__table__.create(sync))
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as db:
            original = NazkWatch(owner_id=1, declarant_id=123, label="Old watch")
            db.add(original)
            await db.commit()
            watch_id = original.id

            async def replace_watch(_target):
                async with sessions() as other:
                    await other.execute(delete(NazkWatch).where(NazkWatch.id == watch_id))
                    other.add(NazkWatch(id=watch_id, owner_id=2, declarant_id=456, label="New watch"))
                    await other.commit()
                if failure:
                    raise NazkSourceError("old watch failed")
                return {"a"}

            monkeypatch.setattr("app.services.nazk_monitoring._snapshot", replace_watch)
            await run_watch(db, watch_id)
            db.expire_all()
            replacement = await db.get(NazkWatch, watch_id)
            assert replacement.label == "New watch"
            assert replacement.last_status == "pending"
            assert replacement.last_error is None
            assert not replacement.baseline_complete
            assert not (await db.execute(select(NazkWatchDocument))).scalars().all()
            assert not (await db.execute(select(Notification))).scalars().all()
        await engine.dispose()
    asyncio.run(exercise())


def test_simultaneous_workers_only_run_one_check(monkeypatch, tmp_path):
    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "concurrent.db"))
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync: User.__table__.create(sync))
            await conn.run_sync(lambda sync: Notification.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatch.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatchDocument.__table__.create(sync))
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup:
            watch = NazkWatch(owner_id=1, declarant_id=123, label="Person")
            setup.add(watch)
            await setup.commit()
            watch_id = watch.id
        entered, release = asyncio.Event(), asyncio.Event()
        calls = 0

        async def snapshot(_target):
            nonlocal calls
            calls += 1
            entered.set()
            await release.wait()
            return {"a"}

        monkeypatch.setattr("app.services.nazk_monitoring._snapshot", snapshot)
        async with sessions() as first, sessions() as second:
            first_run = asyncio.create_task(run_watch(first, watch_id))
            await asyncio.wait_for(entered.wait(), 5)
            try:
                assert not await run_watch(second, watch_id)
            finally:
                release.set()
            assert await first_run
            assert calls == 1
        await engine.dispose()
    asyncio.run(exercise())


def test_watches_are_owned_and_duplicates_rejected(monkeypatch, tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "nazk.db"))
    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync: User.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatch.__table__.create(sync))
            await conn.run_sync(lambda sync: NazkWatchDocument.__table__.create(sync))
    asyncio.run(setup())
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    owner = {"id": 1}

    async def db_override():
        async with sessions() as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, db_override)
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: User(id=owner["id"]))
    client = TestClient(app)
    payload = {"declarant_id": 123, "label": "Person"}
    response = client.post("/api/v1/nazk/watches", json=payload)
    assert response.status_code == 201
    watch_id = response.json()["id"]
    async def insert_changes():
        async with sessions() as db:
            db.add_all([
                NazkWatchDocument(watch_id=watch_id, document_id=f"{i:036d}", discovered_after_baseline=True)
                for i in range(55)
            ])
            db.add(NazkWatchDocument(watch_id=watch_id, document_id="baseline"))
            await db.commit()
    asyncio.run(insert_changes())
    assert client.post("/api/v1/nazk/watches", json=payload).status_code == 409
    assert client.post("/api/v1/nazk/watches", json={"label": "Invalid"}).status_code == 422
    owner["id"] = 2
    assert client.get("/api/v1/nazk/watches").json() == []
    assert client.delete(f"/api/v1/nazk/watches/{watch_id}").status_code == 404
    assert client.get(f"/api/v1/nazk/watches/{watch_id}/changes").status_code == 404
    owner["id"] = 1
    watches = client.get("/api/v1/nazk/watches").json()
    assert len(watches) == 1 and watches[0]["new_count"] == 55
    changes = client.get(f"/api/v1/nazk/watches/{watch_id}/changes")
    assert changes.headers["cache-control"] == "no-store"
    assert len(changes.json()) == 50
    assert changes.json()[0]["source_url"].startswith("https://public.nazk.gov.ua/documents/")
    assert len(client.get(f"/api/v1/nazk/watches/{watch_id}/changes?offset=50").json()) == 5
    assert client.delete(f"/api/v1/nazk/watches/{watch_id}").status_code == 204
    asyncio.run(engine.dispose())
