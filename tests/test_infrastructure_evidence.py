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
from app.models import InfraFinding, InfraInvestigation, User


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
