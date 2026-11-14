"""Read-only search clients for public US and UK case-law sources."""
import asyncio
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit
import xml.etree.ElementTree as ET

import httpx


COURTLISTENER_API = "https://www.courtlistener.com/api/rest/v4/search/"
COURTLISTENER_SITE = "https://www.courtlistener.com"
FIND_CASE_LAW_API = "https://caselaw.nationalarchives.gov.uk/atom.xml"
FIND_CASE_LAW_SITE = "https://caselaw.nationalarchives.gov.uk"
ATOM_NAMESPACE = "{http://www.w3.org/2005/Atom}"
TNA_NAMESPACE = "{https://caselaw.nationalarchives.gov.uk}"


class CaseLawSourceError(Exception):
    """A case-law provider returned an error or an invalid response."""


class _HTMLTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str):
        self.parts.append(data)


def _plain_text(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parser = _HTMLTextParser()
    parser.feed(value)
    text = " ".join(" ".join(parser.parts).split())
    return text or None


def _courtlistener_url(path: object) -> str | None:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return None
    return urljoin(COURTLISTENER_SITE, path)


def _find_case_law_url(entry: ET.Element) -> str | None:
    for link in entry.findall(f"{ATOM_NAMESPACE}link"):
        if link.get("rel") != "alternate" or link.get("type"):
            continue
        href = link.get("href", "")
        parsed = urlsplit(href)
        if parsed.scheme == "https" and parsed.hostname == urlsplit(FIND_CASE_LAW_SITE).hostname:
            return href
    return None


def _element_text(parent: ET.Element, path: str) -> str | None:
    element = parent.find(path)
    if element is None or not element.text:
        return None
    return element.text.strip() or None


def _neutral_citation(entry: ET.Element) -> str | None:
    for identifier in entry.findall(f"{TNA_NAMESPACE}identifier"):
        if identifier.get("type") == "ukncn" and identifier.text:
            return identifier.text.strip()
    return None


class CourtListenerClient:
    async def search(self, query: str, limit: int, api_token: str = "") -> list[dict]:
        if not api_token:
            raise CaseLawSourceError("CourtListener API token is not configured")
        headers = {"Accept": "application/json"}
        headers["Authorization"] = f"Token {api_token}"
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
                response = await client.get(
                    COURTLISTENER_API,
                    params={"q": query, "type": "o", "page_size": limit},
                    headers=headers,
                )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            raise CaseLawSourceError(
                f"CourtListener returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise CaseLawSourceError("Could not connect to CourtListener") from exc
        except ValueError as exc:
            raise CaseLawSourceError("CourtListener returned invalid JSON") from exc

        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            raise CaseLawSourceError("CourtListener returned an unexpected response")

        retrieved_at = datetime.now(timezone.utc).isoformat()
        return [
            {
                "jurisdiction": "US",
                "source": "CourtListener",
                "source_type": "aggregated_case_law",
                "case_name": item.get("caseName"),
                "court": item.get("court"),
                "date": item.get("dateFiled"),
                "citations": [
                    citation for citation in item.get("citation", [])
                    if isinstance(citation, str)
                ],
                "docket_number": item.get("docketNumber"),
                "snippet": _plain_text(item.get("snippet")),
                "source_url": _courtlistener_url(item.get("absolute_url")),
                "retrieved_at": retrieved_at,
            }
            for item in payload["results"][:limit]
            if isinstance(item, dict)
        ]


class FindCaseLawClient:
    async def search(self, query: str, limit: int) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
                response = await client.get(
                    FIND_CASE_LAW_API,
                    params={"query": query, "per_page": limit, "minimum_availability": "metadata"},
                    headers={"Accept": "application/atom+xml, application/xml"},
                )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise CaseLawSourceError(
                f"Find Case Law returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise CaseLawSourceError("Could not connect to Find Case Law") from exc

        try:
            feed = ET.fromstring(response.content)
        except (ET.ParseError, UnicodeDecodeError):
            raise CaseLawSourceError("Find Case Law returned an invalid Atom feed")
        if feed.tag != f"{ATOM_NAMESPACE}feed":
            raise CaseLawSourceError("Find Case Law returned an unexpected XML response")
        entries = feed.findall(f"{ATOM_NAMESPACE}entry")

        retrieved_at = datetime.now(timezone.utc).isoformat()
        results = []
        for entry in entries[:limit]:
            results.append({
                "jurisdiction": "GB",
                "source": "The National Archives Find Case Law",
                "source_type": "official_case_law_repository",
                "case_name": _element_text(entry, f"{ATOM_NAMESPACE}title"),
                "court": _element_text(
                    entry,
                    f"{ATOM_NAMESPACE}author/{ATOM_NAMESPACE}name",
                ),
                "date": _element_text(entry, f"{ATOM_NAMESPACE}published"),
                "neutral_citation": _neutral_citation(entry),
                "source_url": _find_case_law_url(entry),
                "retrieved_at": retrieved_at,
            })
        return results


async def search_case_law(
    query: str,
    limit: int,
    courtlistener_api_token: str = "",
) -> dict:
    providers = {
        "US": ("CourtListener", CourtListenerClient().search(query, limit, courtlistener_api_token)),
        "GB": ("The National Archives Find Case Law", FindCaseLawClient().search(query, limit)),
    }
    jurisdictions = list(providers)
    responses = await asyncio.gather(
        *(providers[jurisdiction][1] for jurisdiction in jurisdictions),
        return_exceptions=True,
    )

    results = {}
    source_status = {}
    for jurisdiction, response in zip(jurisdictions, responses):
        source = providers[jurisdiction][0]
        if isinstance(response, CaseLawSourceError):
            results[jurisdiction] = []
            source_status[jurisdiction] = {
                "source": source,
                "ok": False,
                "error": str(response),
            }
        elif isinstance(response, Exception):
            raise response
        else:
            results[jurisdiction] = response
            source_status[jurisdiction] = {"source": source, "ok": True}

    if not any(status["ok"] for status in source_status.values()):
        failures = "; ".join(
            f"{jurisdiction}: {status['error']}"
            for jurisdiction, status in source_status.items()
        )
        raise CaseLawSourceError(f"No case-law sources could be searched ({failures})")

    return {
        "query": query,
        "results": results,
        "source_status": source_status,
        "coverage_notice": (
            "Results cover publicly available opinions and published judgments, not every court "
            "case, docket entry, or filing. Coverage varies by source and court."
        ),
        "uk_licensing_notice": (
            "Find Case Law's Open Justice Licence does not permit bulk computational analysis; "
            "obtain the required permission before using the data for that purpose."
        ),
        "us_query_privacy_notice": (
            "The US search term is sent to CourtListener, which may log search queries. "
            "Do not submit confidential or sensitive personal information."
            if courtlistener_api_token else
            "A CourtListener API token is not configured, so no US search query was sent."
        ),
    }
