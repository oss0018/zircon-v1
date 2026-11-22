import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.config import settings
from app.main import app
from app.schemas import EntityRegistryCompareRequest
from app.services.entity_registry import (
    CompaniesHouseClient,
    RegistryLookupError,
    build_comparison,
)


def test_company_name_search_maps_official_registry_results(monkeypatch):
    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "items": [{
                    "company_name": "EXAMPLE LIMITED",
                    "company_number": "01234567",
                    "company_status": "active",
                    "type": "ltd",
                    "date_of_creation": "2001-02-03",
                    "address": {"locality": "Cardiff"},
                    "registered_office_address": {
                        "address_line_1": "1 High Street",
                        "locality": "Cardiff",
                        "postal_code": "CF10 1AA",
                    },
                }]
            }

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, params=None, auth=None):
            assert url.endswith("/search/companies")
            assert params == {"q": "Example", "items_per_page": 5}
            assert auth == ("test-key", "")
            return _Response()

    monkeypatch.setattr("app.services.entity_registry.httpx.AsyncClient", _Client)
    results = asyncio.run(CompaniesHouseClient("test-key").lookup("Example", None))

    assert results[0]["jurisdiction"] == "GB"
    assert results[0]["source_type"] == "official_registry"
    assert results[0]["company_number"] == "01234567"
    assert results[0]["registered_address"] == "1 High Street, Cardiff, CF10 1AA"
    assert results[0]["source_url"].endswith("/company/01234567")


def test_company_number_lookup_escapes_number_and_maps_company_detail(monkeypatch):
    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"company_name": "Example Ltd", "company_number": "01234567"}

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, params=None, auth=None):
            assert url.endswith("/company/01234567")
            assert params is None
            return _Response()

    monkeypatch.setattr("app.services.entity_registry.httpx.AsyncClient", _Client)
    results = asyncio.run(CompaniesHouseClient("test-key").lookup(None, "01234567"))
    assert results[0]["name"] == "Example Ltd"


def test_companies_house_http_failures_are_reported(monkeypatch):
    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            request = httpx.Request("GET", "https://api.company-information.service.gov.uk/search/companies")
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("upstream failure", request=request, response=response)

    monkeypatch.setattr("app.services.entity_registry.httpx.AsyncClient", _Client)
    with pytest.raises(RegistryLookupError, match="HTTP 503"):
        asyncio.run(CompaniesHouseClient("test-key").lookup("Example", None))


def test_comparison_marks_delaware_input_unverified_and_does_not_claim_identity():
    response = build_comparison(
        [{"company_number": "01234567", "name": "Example Limited"}],
        {"name": "Example Limited", "entity_number": "1234567"},
        "Example",
    )

    assert response["delaware_record"]["source_type"] == "user_supplied"
    assert response["delaware_record"]["retrieved_at"] is None
    assert "not been verified" in response["delaware_record_notice"]
    assert response["comparisons"][0]["interpretation"] == "strong_textual_similarity"
    assert "not proof" in response["comparison_notice"]


def test_entity_registry_request_requires_a_uk_lookup_and_sanitizes_fields():
    with pytest.raises(ValueError, match="Provide a company name"):
        EntityRegistryCompareRequest(delaware_name="Example Inc")

    request = EntityRegistryCompareRequest(
        query="  Example Ltd  ",
        delaware_name="Example Inc",
    )
    assert request.query == "Example Ltd"


def test_compare_endpoint_requires_api_key_and_returns_registry_comparison(monkeypatch):
    async def fake_lookup(self, query, company_number):
        assert query == "Example"
        assert company_number is None
        return [{"company_number": "01234567", "name": "Example Limited"}]

    monkeypatch.setattr(settings, "companies_house_api_key", "")
    monkeypatch.setattr(CompaniesHouseClient, "lookup", fake_lookup)
    client = TestClient(app)
    unauthorized = client.post(
        "/api/v1/entity-registry/compare",
        json={"query": "Example"},
    )
    assert unauthorized.status_code == 401

    app.dependency_overrides[get_current_user] = lambda: object()
    try:
        missing_key = client.post(
            "/api/v1/entity-registry/compare",
            json={"query": "Example"},
        )
        assert missing_key.status_code == 503

        monkeypatch.setattr(settings, "companies_house_api_key", "test-key")
        response = client.post(
            "/api/v1/entity-registry/compare",
            json={
                "query": "Example",
                "delaware_name": "Example Limited",
                "delaware_entity_number": "1234567",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    data = response.json()
    assert data["uk_results"][0]["company_number"] == "01234567"
    assert data["delaware_record"]["source_type"] == "user_supplied"
    assert data["comparisons"][0]["interpretation"] == "strong_textual_similarity"


def test_cyprus_manual_record_is_unverified_and_does_not_require_uk_api_key(monkeypatch):
    client = TestClient(app)
    assert client.post("/api/v1/entity-registry/cyprus", json={"name": "Example"}).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: object()
    monkeypatch.setattr(settings, "companies_house_api_key", "")
    try:
        assert client.post("/api/v1/entity-registry/cyprus", json={"status": "active"}).status_code == 422
        response = client.post("/api/v1/entity-registry/cyprus", json={
            "name": " Example Ltd ", "company_number": "HE 123", "status": "active",
        })
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    record = response.json()["record"]
    assert record["name"] == "Example Ltd"
    assert record["source_type"] == "user_supplied"
    assert record["retrieved_at"] is None
    assert record["source_url"].startswith("https://efiling.drcor.mcit.gov.cy/")
    assert "not been verified" in response.json()["notice"]


def test_curacao_manual_record_uses_official_search_and_is_unverified(monkeypatch):
    client = TestClient(app)
    assert client.post("/api/v1/entity-registry/curacao", json={"name": "Example"}).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: object()
    monkeypatch.setattr(settings, "companies_house_api_key", "")
    try:
        assert client.post("/api/v1/entity-registry/curacao", json={"status": "active"}).status_code == 422
        response = client.post("/api/v1/entity-registry/curacao", json={
            "name": " Example ", "company_number": "12345", "status": "active",
        })
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    record = response.json()["record"]
    assert record["name"] == "Example"
    assert record["jurisdiction"] == "CW"
    assert record["source_type"] == "user_supplied"
    assert record["retrieved_at"] is None
    assert record["source_url"] == "https://www.curacaochamberofcommerce.com/registry-services/registry-search/"
    assert "not been verified" in response.json()["notice"]
