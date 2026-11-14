import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.main import app
from app.services.case_law import (
    CaseLawSourceError,
    CourtListenerClient,
    FindCaseLawClient,
    search_case_law,
)


def test_courtlistener_search_maps_opinion_results_and_uses_optional_auth(monkeypatch):
    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "count": 1,
                "results": [{
                    "caseName": "Example Corp. v. Smith",
                    "court": "United States Court of Appeals",
                    "dateFiled": "2025-02-01",
                    "citation": ["100 F.4th 10"],
                    "docketNumber": "24-1234",
                    "snippet": "<mark>Example</mark> Corp prevailed.",
                    "absolute_url": "/opinion/1/example-corp-v-smith/",
                }],
            }

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, params=None, headers=None):
            assert url.endswith("/api/rest/v4/search/")
            assert params == {"q": "Example Corp", "type": "o", "page_size": 5}
            assert headers == {
                "Accept": "application/json",
                "Authorization": "Token test-token",
            }
            return _Response()

    monkeypatch.setattr("app.services.case_law.httpx.AsyncClient", _Client)
    results = asyncio.run(CourtListenerClient().search("Example Corp", 5, "test-token"))

    assert results[0]["jurisdiction"] == "US"
    assert results[0]["source_type"] == "aggregated_case_law"
    assert results[0]["citations"] == ["100 F.4th 10"]
    assert results[0]["snippet"] == "Example Corp prevailed."
    assert results[0]["source_url"] == "https://www.courtlistener.com/opinion/1/example-corp-v-smith/"


def test_find_case_law_search_maps_atom_results_and_neutral_citation(monkeypatch):
    atom_feed = b"""<?xml version="1.0" encoding="utf-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom" xmlns:tna="https://caselaw.nationalarchives.gov.uk">
      <entry>
        <title>Example Ltd v Example Authority</title>
        <link href="https://caselaw.nationalarchives.gov.uk/ewhc/2025/10" rel="alternate"/>
        <published>2025-01-10T00:00:00+00:00</published>
        <author><name>High Court</name></author>
        <tna:identifier slug="ewhc/2025/10" type="ukncn">[2025] EWHC 10</tna:identifier>
      </entry>
    </feed>"""

    class _Response:
        content = atom_feed

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, params=None, headers=None):
            assert url == "https://caselaw.nationalarchives.gov.uk/atom.xml"
            assert params == {
                "query": "Example Ltd",
                "per_page": 5,
                "minimum_availability": "metadata",
            }
            return _Response()

    monkeypatch.setattr("app.services.case_law.httpx.AsyncClient", _Client)
    results = asyncio.run(FindCaseLawClient().search("Example Ltd", 5))

    assert results[0]["jurisdiction"] == "GB"
    assert results[0]["source_type"] == "official_case_law_repository"
    assert results[0]["court"] == "High Court"
    assert results[0]["neutral_citation"] == "[2025] EWHC 10"
    assert results[0]["source_url"] == "https://caselaw.nationalarchives.gov.uk/ewhc/2025/10"


def test_case_law_search_returns_partial_results_and_provider_error(monkeypatch):
    async def fail_us(self, *_args):
        raise CaseLawSourceError("CourtListener returned HTTP 503")

    async def search_uk(self, *_args):
        return [{"case_name": "A judgment"}]

    monkeypatch.setattr(CourtListenerClient, "search", fail_us)
    monkeypatch.setattr(FindCaseLawClient, "search", search_uk)
    response = asyncio.run(search_case_law("Example", 5))

    assert response["results"]["US"] == []
    assert response["source_status"]["US"]["ok"] is False
    assert response["source_status"]["US"]["error"] == "CourtListener returned HTTP 503"
    assert response["results"]["GB"][0]["case_name"] == "A judgment"
    assert "no US search query was sent" in response["us_query_privacy_notice"]


def test_case_law_search_fails_if_both_sources_fail(monkeypatch):
    async def fail(self, *_args):
        raise CaseLawSourceError("source unavailable")

    monkeypatch.setattr(CourtListenerClient, "search", fail)
    monkeypatch.setattr(FindCaseLawClient, "search", fail)
    with pytest.raises(CaseLawSourceError, match="No case-law sources could be searched"):
        asyncio.run(search_case_law("Example", 5))


def test_case_law_endpoint_is_authenticated_and_returns_both_jurisdictions(monkeypatch):
    async def fake_search(query, limit, token):
        assert query == "Example Corp"
        assert limit == 3
        assert token == ""
        return {"query": query, "results": {"US": [], "GB": []}}

    monkeypatch.setattr("app.api.case_law.search_case_law", fake_search)
    monkeypatch.setattr("app.api.case_law.settings.courtlistener_api_token", "")
    client = TestClient(app)
    unauthorized = client.post(
        "/api/v1/case-law/search",
        json={"query": "Example Corp"},
    )
    assert unauthorized.status_code == 401

    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: object())
    response = client.post(
        "/api/v1/case-law/search",
        json={"query": "Example Corp", "limit": 3},
    )

    assert response.status_code == 200
    assert set(response.json()["results"]) == {"US", "GB"}


def test_courtlistener_upstream_errors_are_explicit(monkeypatch):
    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            request = httpx.Request("GET", "https://www.courtlistener.com/api/rest/v4/search/")
            response = httpx.Response(429, request=request)
            raise httpx.HTTPStatusError("rate limited", request=request, response=response)

    monkeypatch.setattr("app.services.case_law.httpx.AsyncClient", _Client)
    with pytest.raises(CaseLawSourceError, match="HTTP 429"):
        asyncio.run(CourtListenerClient().search("Example", 5, "test-token"))


def test_courtlistener_search_requires_token_before_network_access(monkeypatch):
    def unexpected_client(**_kwargs):
        raise AssertionError("Should not make an unauthenticated request")

    monkeypatch.setattr("app.services.case_law.httpx.AsyncClient", unexpected_client)
    with pytest.raises(CaseLawSourceError, match="API token is not configured"):
        asyncio.run(CourtListenerClient().search("Example", 5))
