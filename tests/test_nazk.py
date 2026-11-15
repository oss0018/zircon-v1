import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.main import app
from app.services.nazk import NazkSourceError, search_declarations


DOCUMENT_ID = "210f5cfe-d5e9-4af8-8b6c-226b2eba6819"


def _client(monkeypatch, payload, expected_params=None, status=200):
    class Client:
        def __init__(self, **kwargs):
            assert kwargs["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def get(self, url, params, headers):
            assert url == "https://public-api.nazk.gov.ua/v2/documents/list"
            assert headers == {"Accept": "application/json"}
            if expected_params is not None:
                assert params == expected_params
            return httpx.Response(status, json=payload, request=httpx.Request("GET", url))

    monkeypatch.setattr("app.services.nazk.httpx.AsyncClient", Client)


def test_search_maps_only_metadata_and_official_link(monkeypatch):
    _client(monkeypatch, {
        "count": 101,
        "data": [{
            "id": DOCUMENT_ID,
            "data": {"step_1": {"data": {
                "lastname": "Example", "firstname": "Person",
                "workPlace": "Agency", "workPost": "Officer",
                "taxNumber": "not for output",
            }}, "step_2": {"data": "not for output"}},
            "type": 1, "declaration_year": 2025, "declaration_type": 1,
            "date": "2026-03-01T10:00:00+02:00",
        }],
    }, {"query": "Example", "workPlaceEdrpou": "01234567", "page": 2})
    result = asyncio.run(search_declarations("Example", "01234567", 2))
    assert result["count"] == 101 and result["page"] == 2
    assert result["results"][0]["name"] == "Example Person"
    assert result["results"][0]["source_url"] == "https://public.nazk.gov.ua/documents/" + DOCUMENT_ID
    assert "not for output" not in str(result)


@pytest.mark.parametrize("payload", [
    {"error": 1310101},
    {"data": []},
    {"count": 1, "data": [{"id": "//evil.example"}]},
])
def test_malformed_provider_responses_are_errors(monkeypatch, payload):
    _client(monkeypatch, payload)
    with pytest.raises(NazkSourceError):
        asyncio.run(search_declarations("Example", None, 1))


def test_provider_http_failure_is_explicit(monkeypatch):
    _client(monkeypatch, {}, status=429)
    with pytest.raises(NazkSourceError, match="HTTP 429"):
        asyncio.run(search_declarations("Example", None, 1))


def test_endpoint_auth_validation_and_no_store(monkeypatch):
    client = TestClient(app)
    assert client.post("/api/v1/nazk/search", json={"query": "Example"}).status_code == 401
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: object())

    async def fake_search(query, workplace_edrpou, page):
        assert (query, workplace_edrpou, page) == ("Example", "01234567", 2)
        return {"results": [], "count": 0, "page": page}

    monkeypatch.setattr("app.api.nazk.search_declarations", fake_search)
    response = client.post("/api/v1/nazk/search", json={
        "query": " Example ", "workplace_edrpou": "01234567", "page": 2,
    })
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    for data in ({}, {"query": "ab"}, {"query": "   "}, {"workplace_edrpou": "123"},
                 {"query": "Example", "page": 101}):
        assert client.post("/api/v1/nazk/search", json=data).status_code == 422


def test_endpoint_exposes_source_failure(monkeypatch):
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: object())

    async def fail(*_args):
        raise NazkSourceError("NACP register returned HTTP 429")

    monkeypatch.setattr("app.api.nazk.search_declarations", fail)
    response = TestClient(app).post("/api/v1/nazk/search", json={"query": "Example"})
    assert response.status_code == 502
    assert response.json()["detail"] == "NACP register returned HTTP 429"
    assert response.headers["cache-control"] == "no-store"
