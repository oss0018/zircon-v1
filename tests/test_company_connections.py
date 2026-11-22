import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_current_user
from app.api.company_connections import ConnectionRequest, company_connection_graph
from app.database import get_db
from app.main import app
from app.models import InfraFinding, InfraInvestigation


def test_graph_shared_indicators_and_provenance():
    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(InfraInvestigation.__table__.create)
            await conn.run_sync(InfraFinding.__table__.create)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as db:
            db.add_all([
                InfraInvestigation(id=1, target="a.example", target_type="domain", status="completed"),
                InfraInvestigation(id=2, target="b.example", target_type="domain", status="completed"),
                InfraInvestigation(id=3, target="c.example", target_type="domain", status="completed"),
                InfraFinding(id=1, investigation_id=1, module="dns", finding_type="historical_dns", entity="192.0.2.1", source="source-a"),
                InfraFinding(id=2, investigation_id=2, module="dns", finding_type="historical_dns", entity="192.0.2.1", source="source-b"),
                InfraFinding(id=3, investigation_id=3, module="dns", finding_type="subdomain", entity="A.Example.", source="source-c"),
                InfraFinding(id=4, investigation_id=1, module="tech_stack", finding_type="detected_tech", entity="Apache", source="source-a"),
                InfraFinding(id=5, investigation_id=2, module="tech_stack", finding_type="detected_tech", entity="Apache", source="source-b"),
                InfraFinding(id=6, investigation_id=2, module="dns", finding_type="reverse_ip", entity="192.0.2.1", source="fallback"),
            ])
            await db.commit()
            request = ConnectionRequest(companies=[
                {"name": "A", "investigation_ids": [1]},
                {"name": "B", "investigation_ids": [2]},
                {"name": "C", "investigation_ids": [3]},
            ])
            result = await company_connection_graph(request, db, object())
            shared = {(i["type"], i["value"]): i for i in result["shared_indicators"]}
            assert set(shared) == {("ip", "192.0.2.1"), ("domain", "a.example")}
            assert [c["company_index"] for c in shared[("ip", "192.0.2.1")]["companies"]] == [0, 1]
            assert shared[("ip", "192.0.2.1")]["companies"][1]["evidence"][0]["finding_id"] == 2
            assert shared[("domain", "a.example")]["companies"][0]["evidence"][0]["source"] == "user_assigned_target"
            assert "not proof" in result["notice"]
            missing = ConnectionRequest(companies=[
                {"name": "A", "investigation_ids": [1]},
                {"name": "B", "investigation_ids": [999]},
            ])
            with pytest.raises(HTTPException) as error:
                await company_connection_graph(missing, db, object())
            assert error.value.status_code == 404
            db.add(InfraInvestigation(id=4, target="d.example", target_type="domain", status="running"))
            await db.commit()
            missing.companies[1].investigation_ids = [4]
            with pytest.raises(HTTPException) as error:
                await company_connection_graph(missing, db, object())
            assert error.value.status_code == 409
        await engine.dispose()
    asyncio.run(exercise())


def test_request_validation_and_authentication():
    with pytest.raises(ValueError):
        ConnectionRequest(companies=[
            {"name": "  A ", "investigation_ids": [1]},
            {"name": "a", "investigation_ids": [2]},
        ])
    with pytest.raises(ValueError):
        ConnectionRequest(companies=[
            {"name": "A", "investigation_ids": [1, 1]},
            {"name": "B", "investigation_ids": [2]},
        ])
    client = TestClient(app)
    response = client.post("/api/v1/company-connections/graph", json={
        "companies": [{"name": "A", "investigation_ids": [1]}, {"name": "B", "investigation_ids": [2]}],
    })
    assert response.status_code == 401


def test_authenticated_graph_endpoint(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "connections.db"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            await conn.run_sync(InfraInvestigation.__table__.create)
            await conn.run_sync(InfraFinding.__table__.create)
        async with sessions() as db:
            db.add_all([
                InfraInvestigation(id=1, target="shared.example", target_type="domain", status="completed"),
                InfraInvestigation(id=2, target="shared.example", target_type="domain", status="completed"),
            ])
            await db.commit()

    async def override_db():
        async with sessions() as db:
            yield db

    asyncio.run(setup())
    app.dependency_overrides[get_current_user] = lambda: object()
    app.dependency_overrides[get_db] = override_db
    try:
        response = TestClient(app).post("/api/v1/company-connections/graph", json={
            "companies": [{"name": "A", "investigation_ids": [1]}, {"name": "B", "investigation_ids": [2]}],
        })
        assert response.status_code == 200
        assert response.json()["shared_indicators"][0]["value"] == "shared.example"
    finally:
        app.dependency_overrides.clear()
        asyncio.run(engine.dispose())
