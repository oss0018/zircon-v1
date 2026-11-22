import asyncio
import json

import httpx
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


def test_wallet_assignment_validation():
    wallet = {"chain": "btc", "address": "bc1q" + "q" * 20}
    for companies in (
        [{"name": "A"}, {"name": "B", "wallets": [wallet]}],
        [{"name": "A", "wallets": [wallet, {**wallet, "address": wallet["address"].upper()}]},
         {"name": "B", "wallets": [wallet]}],
        [{"name": "A", "wallets": [{"chain": "btc", "address": "invalid"}]},
         {"name": "B", "wallets": [wallet]}],
    ):
        with pytest.raises(ValueError):
            ConnectionRequest(companies=companies)


def test_graph_matches_only_valid_tls_certificate_fingerprints():
    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(InfraInvestigation.__table__.create)
            await conn.run_sync(InfraFinding.__table__.create)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        fingerprint = "ab" * 32
        colon_fingerprint = ":".join(["AB"] * 32)
        async with sessions() as db:
            db.add_all([
                InfraInvestigation(id=1, target="a.example", target_type="domain", status="completed"),
                InfraInvestigation(id=2, target="b.example", target_type="domain", status="completed"),
                InfraFinding(id=1, investigation_id=1, module="cert", finding_type="certificate",
                             entity="a", source="tls_handshake",
                             data_json=json.dumps({"sha256_fingerprint": colon_fingerprint})),
                InfraFinding(id=2, investigation_id=2, module="cert", finding_type="expired_cert",
                             entity="b", source="tls_handshake",
                             data_json=json.dumps({"sha256_fingerprint": fingerprint})),
                InfraFinding(id=3, investigation_id=2, module="cert", finding_type="certificate",
                             entity="b", source="tls_handshake", data_json="not json"),
                InfraFinding(id=4, investigation_id=2, module="cert", finding_type="certificate",
                             entity="b", source="tls_handshake", data_json="{}"),
                InfraFinding(id=5, investigation_id=2, module="cert", finding_type="certificate",
                             entity="b", source="tls_handshake",
                             data_json=json.dumps({"sha256_fingerprint": "ab:" * 32})),
                InfraFinding(id=6, investigation_id=2, module="cert", finding_type="certificate",
                             entity="b", source="crtsh", data_json=json.dumps({
                                 "serial": "123", "sha256_fingerprint": fingerprint,
                             })),
            ])
            await db.commit()
            result = await company_connection_graph(ConnectionRequest(companies=[
                {"name": "A", "investigation_ids": [1]},
                {"name": "B", "investigation_ids": [2]},
                {"name": "C", "investigation_ids": [1]},
            ]), db, object())
            assert result["certificate_coverage"] == {
                "tls_findings": 5, "available": 2, "missing": 1, "malformed": 1, "invalid": 1,
            }
            certs = [item for item in result["shared_indicators"] if item["type"] == "certificate_sha256"]
            assert len(certs) == 1
            shared = certs[0]
            assert (shared["type"], shared["value"]) == ("certificate_sha256", fingerprint)
            assert [company["company_index"] for company in shared["companies"]] == [0, 1, 2]
            assert [company["evidence"][0]["finding_id"] for company in shared["companies"]] == [1, 2, 1]
            assert all(company["evidence"][0]["source"] == "tls_handshake"
                       and company["evidence"][0]["recorded_at"]
                       for company in shared["companies"])
            assert "not independent evidence" in result["notice"]
        await engine.dispose()
    asyncio.run(exercise())


def test_graph_compares_network_ips_with_dns_and_reports_unusable_records():
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
                InfraFinding(id=1, investigation_id=1, module="network", finding_type="open_port",
                             entity="2001:db8::1:443", source="censys",
                             data_json=json.dumps({"ip": "2001:0db8:0:0:0:0:0:1", "port": 443})),
                InfraFinding(id=2, investigation_id=2, module="dns", finding_type="historical_dns",
                             entity="2001:db8::1", source="dns-provider"),
                InfraFinding(id=3, investigation_id=1, module="network", finding_type="open_port",
                             entity="example.com:443", source="fofa", data_json="{}"),
                InfraFinding(id=4, investigation_id=1, module="network", finding_type="open_port",
                             entity="example.com:443", source="fofa", data_json="broken"),
                InfraFinding(id=5, investigation_id=1, module="network", finding_type="open_port",
                             entity="example.com:443", source="fofa", data_json='{"ip": "not-an-ip"}'),
                InfraFinding(id=6, investigation_id=2, module="network", finding_type="other",
                             entity="ignored", source="other", data_json='{"ip": "2001:db8::1"}'),
            ])
            await db.commit()
            result = await company_connection_graph(ConnectionRequest(companies=[
                {"name": "A", "investigation_ids": [1]},
                {"name": "B", "investigation_ids": [2]},
            ]), db, object())
            assert result["network_coverage"] == {
                "open_port_findings": 4, "available": 1, "missing": 1, "malformed": 1, "invalid": 1,
            }
            assert len(result["shared_indicators"]) == 1
            shared = result["shared_indicators"][0]
            assert (shared["type"], shared["value"]) == ("ip", "2001:db8::1")
            assert [company["evidence"][0]["finding_id"] for company in shared["companies"]] == [1, 2]
            assert [company["evidence"][0]["source"] for company in shared["companies"]] == [
                "censys", "dns-provider",
            ]
        await engine.dispose()
    asyncio.run(exercise())


def test_graph_compares_tls_endpoint_ips_independently_of_fingerprints():
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
                InfraFinding(id=1, investigation_id=1, module="cert", finding_type="certificate",
                             entity="misleading.example:443", source="tls_handshake",
                             data_json=json.dumps({"ip": "2001:0db8::1", "sha256_fingerprint": "ab" * 32})),
                InfraFinding(id=2, investigation_id=2, module="cert", finding_type="self_signed_cert",
                             entity="other.example:443", source="tls_handshake",
                             data_json=json.dumps({"ip": "2001:db8::1", "sha256_fingerprint": "AB" * 32})),
                InfraFinding(id=3, investigation_id=1, module="cert", finding_type="expired_cert",
                             entity="192.0.2.1:443", source="tls_handshake",
                             data_json='{"ip": "192.0.2.1", "sha256_fingerprint": "invalid"}'),
                InfraFinding(id=4, investigation_id=2, module="dns", finding_type="historical_dns",
                             entity="192.0.2.1", source="passive-dns"),
                InfraFinding(id=5, investigation_id=1, module="cert", finding_type="certificate",
                             entity="invalid", source="tls_handshake", data_json="not-json"),
                InfraFinding(id=6, investigation_id=1, module="cert", finding_type="certificate",
                             entity="missing", source="tls_handshake", data_json="{}"),
                InfraFinding(id=7, investigation_id=1, module="cert", finding_type="certificate",
                             entity="invalid", source="tls_handshake", data_json='{"ip": "example.com"}'),
                InfraFinding(id=8, investigation_id=2, module="cert", finding_type="certificate",
                             entity="ignored", source="crtsh", data_json='{"ip": "192.0.2.1"}'),
            ])
            await db.commit()
            result = await company_connection_graph(ConnectionRequest(companies=[
                {"name": "A", "investigation_ids": [1]},
                {"name": "B", "investigation_ids": [2]},
            ]), db, object())
            assert result["tls_endpoint_coverage"] == {
                "tls_findings": 6, "available": 3, "missing": 1, "malformed": 1, "invalid": 1,
            }
            shared = {(item["type"], item["value"]): item for item in result["shared_indicators"]}
            assert set(shared) == {
                ("certificate_sha256", "ab" * 32), ("ip", "2001:db8::1"), ("ip", "192.0.2.1"),
            }
            for key, field in ((("certificate_sha256", "ab" * 32), "sha256_fingerprint"),
                               (("ip", "2001:db8::1"), "ip")):
                evidence = [company["evidence"][0] for company in shared[key]["companies"]]
                assert [item["finding_id"] for item in evidence] == [1, 2]
                assert all(item["indicator_field"] == field and item["source"] == "tls_handshake"
                           for item in evidence)
            evidence = [company["evidence"][0] for company in shared[("ip", "192.0.2.1")]["companies"]]
            assert [item["finding_id"] for item in evidence] == [3, 4]
            assert [item["indicator_field"] for item in evidence] == ["ip", "entity"]
        await engine.dispose()
    asyncio.run(exercise())


def test_authenticated_graph_endpoint(tmp_path, monkeypatch):
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
    async def no_external_requests(*args, **kwargs):
        raise AssertionError("Graph must not request external services")
    monkeypatch.setattr(httpx.AsyncClient, "send", no_external_requests)
    try:
        response = TestClient(app).post("/api/v1/company-connections/graph", json={
            "companies": [{"name": "A", "investigation_ids": [1]}, {"name": "B", "investigation_ids": [2]}],
        })
        assert response.status_code == 200
        assert response.json()["shared_indicators"][0]["value"] == "shared.example"
        btc = "bc1q" + "q" * 20
        tron = "T" + "A" * 33
        response = TestClient(app).post("/api/v1/company-connections/graph", json={
            "companies": [
                {"name": "A", "wallets": [{"chain": "btc", "address": btc.upper()},
                                            {"chain": "usdt_trc20", "address": tron}]},
                {"name": "B", "wallets": [{"chain": "btc", "address": btc},
                                            {"chain": "usdt_trc20", "address": tron}]},
                {"name": "C", "investigation_ids": [1]},
            ],
        })
        assert response.status_code == 200
        data = response.json()
        assert [(item["type"], item["value"]) for item in data["shared_indicators"]] == [
            ("wallet_btc", btc), ("wallet_usdt_trc20", tron),
        ]
        for item in data["shared_indicators"]:
            assert [company["company_index"] for company in item["companies"]] == [0, 1]
            assert all(company["evidence"][0]["source"] == "user_assigned_wallet"
                       and company["evidence"][0]["investigation_id"] is None
                       for company in item["companies"])
        assert "not proof" in data["notice"]
        assert "format-checked only" in data["notice"]
    finally:
        app.dependency_overrides.clear()
        asyncio.run(engine.dispose())
