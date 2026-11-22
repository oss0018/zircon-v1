import asyncio
import hashlib
import io
import json
import zipfile

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_current_user
from app.database import get_db
from app.main import app
from app.models import EvidenceArchive, EvidenceCustodyEvent, InfraFinding, InfraInvestigation, User


def test_export_contains_selected_records_and_verifiable_manifest(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "evidence.db"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(InfraInvestigation.__table__.create)
            await conn.run_sync(InfraFinding.__table__.create)
        async with sessions() as db:
            db.add_all([
                InfraInvestigation(id=1, target="example.com", target_type="domain", status="completed"),
                InfraInvestigation(id=2, target="other.example", target_type="domain", status="completed"),
                InfraFinding(id=1, investigation_id=1, module="dns", finding_type="subdomain", entity="a.example.com", source="crtsh", data_json='{"source":"test"}'),
                InfraFinding(id=2, investigation_id=2, module="dns", finding_type="subdomain", entity="b.example.com", source="other"),
            ])
            await db.commit()

    async def override_db():
        async with sessions() as db:
            yield db

    asyncio.run(setup())
    app.dependency_overrides[get_current_user] = lambda: User(id=3, username="analyst")
    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        response = client.post("/api/v1/evidence/infrastructure", json={"investigation_id": 1, "finding_ids": [1]})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            raw = archive.read("findings.json")
            records = json.loads(raw)
            manifest = json.loads(archive.read("manifest.json"))
            assert manifest["files"][0]["sha256"] == hashlib.sha256(raw).hexdigest()
            assert manifest["files"][0]["bytes"] == len(raw)
            assert records["exported_by"]["username"] == "analyst"
            assert records["findings"][0]["data_json_raw"] == '{"source":"test"}'
            assert records["findings"][0]["source"] == "crtsh"
            assert "does not prove" in manifest["limitations"]
        response = client.post("/api/v1/evidence/infrastructure", json={"investigation_id": 1, "finding_ids": [2]})
        assert response.status_code == 404
    finally:
        app.dependency_overrides.clear()
        asyncio.run(engine.dispose())

    assert TestClient(app).post("/api/v1/evidence/infrastructure", json={
        "investigation_id": 1, "finding_ids": [1],
    }).status_code == 401


def test_saved_packages_are_owner_scoped_immutable_and_audited(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "saved-evidence.db"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            for table in (User.__table__, InfraInvestigation.__table__, InfraFinding.__table__,
                          EvidenceArchive.__table__, EvidenceCustodyEvent.__table__):
                await conn.run_sync(table.create)
        async with sessions() as db:
            db.add_all([
                User(id=1, username="analyst", password_hash="x", role="user"),
                User(id=2, username="other", password_hash="x", role="user"),
                User(id=3, username="admin", password_hash="x", role="admin"),
                InfraInvestigation(id=1, target="example.com", target_type="domain", status="completed"),
                InfraFinding(id=1, investigation_id=1, module="dns", finding_type="subdomain",
                             entity="a.example.com", source="crtsh", data_json="{}"),
            ])
            await db.commit()

    async def override_db():
        async with sessions() as db:
            yield db

    async def tamper():
        async with sessions() as db:
            archive = await db.get(EvidenceArchive, 1)
            archive.archive_bytes = b"modified"
            await db.commit()

    async def delete_original():
        async with sessions() as db:
            finding = await db.get(InfraFinding, 1)
            await db.delete(finding)
            await db.commit()

    asyncio.run(setup())
    actor = {"id": 1, "username": "analyst", "role": "user"}
    app.dependency_overrides[get_current_user] = lambda: User(**actor)
    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        created = client.post("/api/v1/evidence/packages", json={"investigation_id": 1, "finding_ids": [1]})
        assert created.status_code == 201
        assert created.headers["cache-control"] == "no-store"
        package = created.json()
        assert package["id"] == 1
        assert [item["id"] for item in client.get("/api/v1/evidence/packages").json()] == [1]
        actor.update(id=2, username="other")
        assert client.get("/api/v1/evidence/packages").json() == []
        assert client.get("/api/v1/evidence/packages/1/events").status_code == 404
        assert client.get("/api/v1/evidence/packages/1/download").status_code == 404
        actor.update(id=1, username="analyst")
        asyncio.run(delete_original())
        download = client.get("/api/v1/evidence/packages/1/download")
        assert download.status_code == 200
        assert hashlib.sha256(download.content).hexdigest() == package["sha256"]
        with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
            assert json.loads(archive.read("findings.json"))["findings"][0]["id"] == 1
        events = client.get("/api/v1/evidence/packages/1/events").json()
        assert [event["action"] for event in events] == ["download_requested", "package_created"]
        assert all(event["actor_username"] == "analyst" for event in events)
        asyncio.run(tamper())
        assert client.get("/api/v1/evidence/packages/1/download").status_code == 409
        assert client.get("/api/v1/evidence/packages/1/events").json()[0]["action"] == "integrity_check_failed"
        actor.update(id=3, username="admin", role="admin")
        assert client.delete("/api/v1/auth/users/1").status_code == 409
        assert client.delete("/api/v1/auth/users/2").status_code == 200
    finally:
        app.dependency_overrides.clear()
        asyncio.run(engine.dispose())
