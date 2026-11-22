import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.main import app
from app.services import wallet_connections, wallet_monitoring


BTC_A = "1" + "A" * 25
BTC_B = "1" + "B" * 25
TRON_A = "T" + "A" * 33
TRON_B = "T" + "B" * 33
TX1 = "a" * 64
TX2 = "b" * 64


def test_bitcoin_comparison_reports_cooccurrence_without_fund_attribution(monkeypatch):
    shared = {
        "txid": TX1, "status": {"confirmed": True, "block_time": 1700000000},
        "vin": [
            {"prevout": {"scriptpubkey_address": BTC_A, "value": 5000}},
            {"prevout": {"scriptpubkey_address": "someone_else", "value": 6000}},
        ],
        "vout": [
            {"scriptpubkey_address": BTC_B, "value": 3000},
            {"scriptpubkey_address": BTC_A, "value": 7000},
        ],
    }

    def handler(request):
        assert request.url.host == "blockstream.info"
        return httpx.Response(200, json=[shared])

    real_client = httpx.AsyncClient
    monkeypatch.setattr(wallet_monitoring.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    result = asyncio.run(wallet_connections.compare_wallets("btc", [BTC_A, BTC_B]))
    assert len(result["matches"]) == 1
    assert result["matches"][0]["inputs"] == [{"address": BTC_A, "satoshis": 5000}]
    assert result["matches"][0]["outputs"] == [
        {"address": BTC_A, "satoshis": 7000}, {"address": BTC_B, "satoshis": 3000},
    ]
    assert "not proof" in result["notice"]
    assert "amount" not in result["matches"][0]


def test_tron_direct_transfer_comparison_and_authenticated_endpoint(monkeypatch):
    def transfer(txid, sender, receiver, amount):
        return {
            "transaction_id": txid, "type": "Transfer", "from": sender, "to": receiver,
            "value": amount, "block_timestamp": 1700000000000,
            "token_info": {"address": wallet_monitoring.USDT_CONTRACT, "decimals": 6},
        }

    outgoing = transfer(TX1, TRON_A, TRON_B, "1000001")
    second_outgoing = transfer(TX1, TRON_A, TRON_B, "7")
    incoming = transfer(TX2, TRON_B, TRON_A, "42")
    unrelated = transfer("c" * 64, TRON_A, "T" + "C" * 33, "50")

    def handler(request):
        assert request.url.host == "api.trongrid.io"
        assert request.url.params["only_confirmed"] == "true"
        records = [outgoing, second_outgoing, incoming, outgoing]
        if TRON_A in request.url.path:
            records.append(unrelated)
        return httpx.Response(200, json={"success": True, "data": records, "meta": {}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(wallet_monitoring.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    client = TestClient(app)
    body = {"chain": "usdt_trc20", "addresses": [TRON_A, TRON_B]}
    assert client.post("/api/v1/wallet-monitoring/compare", json=body).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: object()
    try:
        response = client.post("/api/v1/wallet-monitoring/compare", json=body)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        result = response.json()
        assert [(item["transaction_id"], item["from"], item["to"], item["amount_base_units"])
                for item in result["matches"]] == [
                    (TX1, TRON_A, TRON_B, "1000001"), (TX1, TRON_A, TRON_B, "7"),
                    (TX2, TRON_B, TRON_A, "42"),
                ]
        assert "collapsed" in result["notice"]
        assert client.post("/api/v1/wallet-monitoring/compare", json={
            "chain": "usdt_trc20", "addresses": [TRON_A, TRON_A],
        }).status_code == 422
    finally:
        app.dependency_overrides.clear()


def test_provider_failures_and_incomplete_data_do_not_return_empty_results(monkeypatch):
    async def failing_history(_chain, _address):
        raise wallet_monitoring.WalletSourceError("Provider returned HTTP 429")

    monkeypatch.setattr(wallet_connections, "_history", failing_history)
    app.dependency_overrides[get_current_user] = lambda: object()
    try:
        response = TestClient(app).post("/api/v1/wallet-monitoring/compare", json={
            "chain": "btc", "addresses": [BTC_A, BTC_B],
        })
        assert response.status_code == 502
        assert response.json()["detail"] == "Provider returned HTTP 429"
        assert response.headers["cache-control"] == "no-store"
    finally:
        app.dependency_overrides.clear()
    with pytest.raises(wallet_monitoring.WalletSourceError, match="incomplete"):
        wallet_connections._bitcoin_addresses([{"prevout": None}], {BTC_A}, inputs=True)


def test_bitcoin_coin_inputs_alone_do_not_create_a_match(monkeypatch):
    async def history(_chain, _address):
        return [{
            "txid": TX1, "status": {"confirmed": True},
            "vin": [
                {"prevout": {"scriptpubkey_address": BTC_A, "value": 5000}},
                {"prevout": {"scriptpubkey_address": BTC_B, "value": 6000}},
            ],
            "vout": [{"scriptpubkey_address": "someone_else", "value": 10000}],
        }]

    monkeypatch.setattr(wallet_connections, "_history", history)
    assert asyncio.run(wallet_connections.compare_wallets("btc", [BTC_A, BTC_B]))["matches"] == []


def test_full_tron_page_without_cursor_is_not_treated_as_complete(monkeypatch):
    approval = {
        "transaction_id": TX1, "type": "Approval",
        "token_info": {"address": wallet_monitoring.USDT_CONTRACT},
    }

    def handler(_request):
        return httpx.Response(200, json={"success": True, "data": [approval] * 200, "meta": {}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(wallet_monitoring.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    with pytest.raises(wallet_monitoring.WalletSourceError, match="full page"):
        asyncio.run(wallet_monitoring._history("usdt_trc20", TRON_A))
