import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.main import app
from app.schemas import RegulatorSearchRequest
from app.services.regulators import (
    RegulatorSourceError,
    SECLitigationReleaseClient,
    build_regulator_response,
)


def test_sec_search_filters_and_maps_official_rss_releases(monkeypatch):
    rss = b"""<?xml version="1.0"?>
    <rss version="2.0"><channel>
      <item>
        <title>SEC Files Action Against Example Corp</title>
        <link>https://www.sec.gov/litigation/litreleases/lr-123</link>
        <description><![CDATA[<p>Alleged <b>fraud</b> involving Example Corp.</p>]]></description>
        <pubDate>Fri, 13 Nov 2026 10:00:00 GMT</pubDate>
      </item>
      <item>
        <title>SEC Announces Other Matter</title>
        <link>https://www.sec.gov/litigation/litreleases/lr-124</link>
        <description>Other matter</description>
      </item>
    </channel></rss>"""

    class _Response:
        content = rss

        def raise_for_status(self):
            pass

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, headers=None):
            assert url.endswith("/rss/litigation/litreleases.xml")
            assert headers["User-Agent"] == "Zircon test contact@example.org"
            return _Response()

    monkeypatch.setattr("app.services.regulators.httpx.AsyncClient", _Client)
    results = asyncio.run(
        SECLitigationReleaseClient().search("Example Corp", 5, "Zircon test contact@example.org")
    )

    assert len(results) == 1
    assert results[0]["jurisdiction"] == "US"
    assert results[0]["record_type"] == "litigation_release"
    assert results[0]["summary"] == "Alleged fraud involving Example Corp."
    assert results[0]["source_url"] == "https://www.sec.gov/litigation/litreleases/lr-123"


def test_sec_search_requires_a_safe_identifying_user_agent(monkeypatch):
    def unexpected_client(**_kwargs):
        raise AssertionError("Should not make a request without a valid User-Agent")

    monkeypatch.setattr("app.services.regulators.httpx.AsyncClient", unexpected_client)
    with pytest.raises(RegulatorSourceError, match="SEC_USER_AGENT is not configured"):
        asyncio.run(SECLitigationReleaseClient().search("Example", 5, ""))
    with pytest.raises(RegulatorSourceError, match="SEC_USER_AGENT is invalid"):
        asyncio.run(SECLitigationReleaseClient().search("Example", 5, "bad\r\nheader"))


def test_regulator_search_validates_fca_links_and_query():
    request = RegulatorSearchRequest(
        query="Example Corp",
        fca_entity_name="Example Corp Ltd",
        fca_source_url="https://www.fca.org.uk/news/example",
        fca_summary="",
    )
    assert request.fca_source_url == "https://www.fca.org.uk/news/example"
    assert request.fca_summary is None

    with pytest.raises(ValueError, match="official FCA HTTPS host"):
        RegulatorSearchRequest(
            query="Example",
            fca_source_url="https://example.org/fca-record",
        )
    with pytest.raises(ValueError, match="Query must not be blank"):
        RegulatorSearchRequest(query=" ")


def test_regulator_response_marks_fca_details_unverified():
    response = build_regulator_response(
        "Example Corp",
        [{"title": "SEC action"}],
        {
            "entity_name": "Example Corp Ltd",
            "reference": "ABC123",
            "action_type": "Final notice",
            "date": "2026-01-10",
            "summary": "Public notice",
            "source_url": "https://www.fca.org.uk/news/example",
        },
    )

    assert response["results"]["US"][0]["title"] == "SEC action"
    assert response["results"]["GB"]["source_type"] == "user_supplied"
    assert response["results"]["GB"]["retrieved_at"] is None
    assert response["source_status"]["GB"]["status"] == "user_supplied_unverified"


def test_regulator_response_keeps_manual_fca_path_when_sec_is_unavailable():
    response = build_regulator_response(
        "Example Corp",
        [],
        None,
        "SEC_USER_AGENT is not configured; no SEC request was sent",
    )
    assert response["source_status"]["US"]["ok"] is False
    assert "SEC_USER_AGENT" in response["source_status"]["US"]["error"]
    assert response["source_status"]["GB"]["status"] == "manual_lookup_required"
    assert response["source_status"]["GB"]["search_url"].startswith("https://www.fca.org.uk/")


def test_regulator_search_endpoint_requires_auth_and_returns_records(monkeypatch):
    async def fake_search(self, query, limit, user_agent):
        assert query == "Example Corp"
        assert limit == 5
        assert user_agent == "Zircon test contact@example.org"
        return [{"title": "SEC action"}]

    monkeypatch.setattr(SECLitigationReleaseClient, "search", fake_search)
    monkeypatch.setattr("app.api.regulators.settings.sec_user_agent", "Zircon test contact@example.org")
    client = TestClient(app)
    unauthorized = client.post(
        "/api/v1/regulators/search",
        json={"query": "Example Corp"},
    )
    assert unauthorized.status_code == 401

    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: object())
    response = client.post(
        "/api/v1/regulators/search",
        json={
            "query": "Example Corp",
            "fca_entity_name": "Example Corp Ltd",
            "fca_source_url": "https://register.fca.org.uk/record/123",
        },
    )

    assert response.status_code == 200
    assert response.json()["results"]["US"][0]["title"] == "SEC action"
    assert response.json()["results"]["GB"]["source_type"] == "user_supplied"


def test_sec_feed_upstream_errors_are_explicit(monkeypatch):
    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            request = httpx.Request("GET", "https://www.sec.gov/rss/litigation/litreleases.xml")
            response = httpx.Response(403, request=request)
            raise httpx.HTTPStatusError("forbidden", request=request, response=response)

    monkeypatch.setattr("app.services.regulators.httpx.AsyncClient", _Client)
    with pytest.raises(RegulatorSourceError, match="HTTP 403"):
        asyncio.run(SECLitigationReleaseClient().search("Example", 5, "Zircon contact@example.org"))
