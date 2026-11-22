import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.main import app
from app.services import wallet_connections, wallet_monitoring


SOURCE = "T" + "A" * 33
DESTINATION = "T" + "B" * 33
MID = "T" + "C" * 33
REVERSED = "T" + "D" * 33
SAME_TIME = "T" + "E" * 33


def transfer(tx_char, sender, receiver, timestamp, value="100"):
    return {
        "transaction_id": tx_char * 64, "type": "Transfer", "from": sender, "to": receiver,
        "value": value, "block_timestamp": timestamp,
        "token_info": {"address": wallet_monitoring.USDT_CONTRACT, "decimals": 6},
    }


def test_trace_finds_direct_and_ordered_two_hop_paths(monkeypatch):
    direct = transfer("a", SOURCE, DESTINATION, 100)
    first = transfer("b", SOURCE, MID, 200)
    second = transfer("c", MID, DESTINATION, 300)
    late = transfer("d", SOURCE, REVERSED, 450)
    earlier = transfer("e", REVERSED, DESTINATION, 400)
    same_first = transfer("f", SOURCE, SAME_TIME, 500)
    same_second = transfer("1", SAME_TIME, DESTINATION, 500)
    requested = []

    def handler(request):
        assert request.url.host == "api.trongrid.io"
        assert request.url.params["only_confirmed"] == "true"
        address = request.url.path.split("/")[3]
        requested.append(address)
        if address == SOURCE:
            data = [direct, first, first, late, same_first]
        elif address == DESTINATION:
            data = [direct, second, earlier, same_second]
        else:
            raise AssertionError("Unexpected intermediary lookup")
        return httpx.Response(200, json={"success": True, "data": data, "meta": {}})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(wallet_monitoring.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    client = TestClient(app)
    body = {"source_address": SOURCE, "destination_address": DESTINATION}
    assert client.post("/api/v1/wallet-monitoring/trace-usdt", json=body).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: object()
    try:
        response = client.post("/api/v1/wallet-monitoring/trace-usdt", json=body)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        result = response.json()
        assert [[leg["transaction_id"] for leg in path["transfers"]] for path in result["paths"]] == [
            ["a" * 64], ["b" * 64, "c" * 64], ["f" * 64, "1" * 64],
        ]
        assert result["paths"][2]["same_timestamp_order_unknown"]
        assert not result["paths"][1]["same_timestamp_order_unknown"]
        assert "not proof" in result["notice"]
        assert requested == [SOURCE, DESTINATION]
        assert client.post("/api/v1/wallet-monitoring/trace-usdt", json={
            "source_address": SOURCE, "destination_address": SOURCE,
        }).status_code == 422
        monkeypatch.setattr(wallet_connections, "MAX_TRACE_PATHS", 1)
        limited = client.post("/api/v1/wallet-monitoring/trace-usdt", json=body)
        assert limited.status_code == 422
        assert "no partial result" in limited.json()["detail"]
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("failure", ["missing_timestamp", "inconsistent_direct", "provider"])
def test_trace_fails_explicitly_when_evidence_is_incomplete(monkeypatch, failure):
    async def history(_chain, address):
        if failure == "provider":
            raise wallet_monitoring.WalletSourceError("Provider returned HTTP 429")
        direct = transfer("a", SOURCE, DESTINATION, 100)
        if failure == "missing_timestamp":
            direct.pop("block_timestamp")
        if failure == "inconsistent_direct" and address == DESTINATION:
            return []
        return [direct]

    monkeypatch.setattr(wallet_connections, "_history", history)
    app.dependency_overrides[get_current_user] = lambda: object()
    try:
        response = TestClient(app).post("/api/v1/wallet-monitoring/trace-usdt", json={
            "source_address": SOURCE, "destination_address": DESTINATION,
        })
        assert response.status_code == 502
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["detail"]
    finally:
        app.dependency_overrides.clear()
