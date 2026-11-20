import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_current_user
from app.api.wallet_monitoring import WalletWatchCreate
from app.database import get_db
from app.main import app
from app.models import Notification, User, WalletWatch, WalletWatchTransaction
from app.services import wallet_monitoring


def test_snapshot_pagination_and_tron_transfer_filter(monkeypatch):
    a, b = "a" * 64, "b" * 64
    address = "TJmmqjb1DK9TTZbQXzRQ2AuA94z4gKAPFh"
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.host == "blockstream.info":
            cursor = request.url.path.split("/")[-1]
            if cursor == "chain":
                return httpx.Response(200, json=[{
                    "txid": f"{i:064x}", "status": {"confirmed": True},
                } for i in range(25)])
            return httpx.Response(200, json=[])
        records = [{
            "transaction_id": a, "type": "Transfer", "from": address, "to": "other",
            "token_info": {"address": wallet_monitoring.USDT_CONTRACT},
        }, {
            "transaction_id": b, "type": "Approval",
            "token_info": {"address": wallet_monitoring.USDT_CONTRACT},
        }]
        return httpx.Response(200, json={"success": True, "data": records, "meta": {}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(wallet_monitoring.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    btc = asyncio.run(wallet_monitoring._snapshot("btc", "address"))
    assert len(btc) == 25
    assert len(calls) == 3
    tron = asyncio.run(wallet_monitoring._snapshot("usdt_trc20", address))
    assert tron == {a}
    assert calls[-1].url.params["only_confirmed"] == "true"
    assert calls[-1].url.params["contract_address"] == wallet_monitoring.USDT_CONTRACT


def test_baseline_changes_failures_and_isolation(monkeypatch):
    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            for table in (User.__table__, Notification.__table__, WalletWatch.__table__, WalletWatchTransaction.__table__):
                await conn.run_sync(table.create)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as db:
            db.add(WalletWatch(id=1, owner_id=1, chain="btc", address="address", label="test"))
            await db.commit()
            state = {"ids": {"a" * 64}, "fail": False}

            async def snapshot(*_args):
                if state["fail"]:
                    raise wallet_monitoring.WalletSourceError("provider unavailable")
                return state["ids"]

            monkeypatch.setattr(wallet_monitoring, "_snapshot", snapshot)
            assert await wallet_monitoring.run_watch(db, 1)
            watch = await db.get(WalletWatch, 1)
            assert watch.baseline_complete
            assert not (await db.execute(select(Notification))).scalars().all()
            watch.last_attempt = datetime.now(timezone.utc) - timedelta(days=2)
            state["ids"] = {"a" * 64, "b" * 64}
            await db.commit()
            assert await wallet_monitoring.run_watch(db, 1)
            items = (await db.execute(select(WalletWatchTransaction))).scalars().all()
            assert {item.transaction_id for item in items if item.discovered_after_baseline} == {"b" * 64}
            notification = (await db.execute(select(Notification))).scalar_one()
            assert "address" not in notification.message
            watch.last_attempt = datetime.now(timezone.utc) - timedelta(days=2)
            await db.commit()
            state["fail"] = True
            assert await wallet_monitoring.run_watch(db, 1)
            await db.refresh(watch)
            assert watch.last_status == "failed"
            assert watch.last_error == "provider unavailable"
            assert len((await db.execute(select(WalletWatchTransaction))).scalars().all()) == 2
        await engine.dispose()
    asyncio.run(exercise())


def test_watch_address_validation():
    assert WalletWatchCreate(chain="usdt_trc20", address="TJmmqjb1DK9TTZbQXzRQ2AuA94z4gKAPFh", label="test").chain == "usdt_trc20"
    with pytest.raises(ValueError):
        WalletWatchCreate(chain="btc", address="../bad", label="test")


def test_watch_endpoints_are_owner_scoped(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "wallets.db"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def setup():
        async with engine.begin() as conn:
            for table in (User.__table__, WalletWatch.__table__, WalletWatchTransaction.__table__):
                await conn.run_sync(table.create)
        async with sessions() as db:
            db.add_all([
                WalletWatch(id=1, owner_id=1, chain="btc", address="a", label="one"),
                WalletWatch(id=2, owner_id=2, chain="btc", address="b", label="two"),
            ])
            await db.commit()

    async def override_db():
        async with sessions() as db:
            yield db

    asyncio.run(setup())
    app.dependency_overrides[get_current_user] = lambda: User(id=1)
    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        response = client.get("/api/v1/wallet-monitoring/watches")
        assert response.status_code == 200
        assert [watch["id"] for watch in response.json()] == [1]
        assert response.headers["cache-control"] == "no-store"
        assert client.get("/api/v1/wallet-monitoring/watches/2/changes").status_code == 404
        assert client.delete("/api/v1/wallet-monitoring/watches/2").status_code == 404
    finally:
        app.dependency_overrides.clear()
        asyncio.run(engine.dispose())
