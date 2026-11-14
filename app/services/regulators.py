"""Published US SEC enforcement releases and FCA user-supplied records."""
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit

import feedparser
import httpx


SEC_LITIGATION_FEED = "https://www.sec.gov/rss/litigation/litreleases.xml"
SEC_SITE_HOSTS = {"sec.gov", "www.sec.gov"}
FCA_ENFORCEMENT_SEARCH = "https://www.fca.org.uk/news/search-results?category=Enforcement"


class RegulatorSourceError(Exception):
    """The SEC enforcement feed could not be retrieved or parsed."""


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


def _is_sec_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname in SEC_SITE_HOSTS
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
    )


class SECLitigationReleaseClient:
    async def search(self, query: str, limit: int, user_agent: str) -> list[dict]:
        user_agent = user_agent.strip()
        if not user_agent:
            raise RegulatorSourceError(
                "SEC_USER_AGENT is not configured; no SEC request was sent"
            )
        if len(user_agent) > 256 or "\r" in user_agent or "\n" in user_agent:
            raise RegulatorSourceError("SEC_USER_AGENT is invalid")
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
                response = await client.get(
                    SEC_LITIGATION_FEED,
                    headers={"Accept": "application/rss+xml, application/xml", "User-Agent": user_agent},
                )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RegulatorSourceError(
                f"SEC litigation feed returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise RegulatorSourceError("Could not connect to the SEC litigation feed") from exc

        feed = feedparser.parse(response.content)
        if feed.bozo and not feed.entries:
            raise RegulatorSourceError("SEC returned an invalid litigation RSS feed")

        query_terms = query.casefold().split()
        retrieved_at = datetime.now(timezone.utc).isoformat()
        results = []
        for entry in feed.entries:
            title = entry.get("title", "")
            summary = _plain_text(entry.get("summary")) or ""
            searchable_text = f"{title} {summary}".casefold()
            if not all(term in searchable_text for term in query_terms):
                continue
            results.append({
                "jurisdiction": "US",
                "source": "U.S. Securities and Exchange Commission",
                "source_type": "official_enforcement_feed",
                "record_type": "litigation_release",
                "title": title,
                "date": entry.get("published"),
                "summary": summary or None,
                "source_url": entry.get("link") if _is_sec_url(entry.get("link")) else None,
                "retrieved_at": retrieved_at,
            })
            if len(results) >= limit:
                break
        return results


def build_regulator_response(
    query: str,
    sec_records: list[dict],
    fca_record: dict | None,
    sec_error: str | None = None,
) -> dict:
    fca = None
    fca_status = "manual_lookup_required"
    if fca_record:
        fca = {
            "jurisdiction": "GB",
            "source": "Financial Conduct Authority",
            "source_type": "user_supplied",
            "record_type": fca_record.get("action_type"),
            "entity_name": fca_record.get("entity_name"),
            "reference": fca_record.get("reference"),
            "date": fca_record.get("date"),
            "summary": fca_record.get("summary"),
            "source_url": fca_record.get("source_url"),
            "retrieved_at": None,
        }
        fca_status = "user_supplied_unverified"

    return {
        "query": query,
        "results": {"US": sec_records, "GB": fca},
        "source_status": {
            "US": {
                "source": "U.S. Securities and Exchange Commission litigation releases",
                "ok": sec_error is None,
                "error": sec_error,
            },
            "GB": {
                "source": "Financial Conduct Authority",
                "status": fca_status,
                "search_url": FCA_ENFORCEMENT_SEARCH,
            },
        },
        "coverage_notice": (
            "US results are limited to recent SEC litigation releases and are not a complete "
            "catalogue of SEC actions. FCA records are not searched automatically in this MVP."
        ),
        "fca_record_notice": (
            "FCA details are user-provided and have not been verified against FCA records."
            if fca else
            "Use the official FCA enforcement search, then provide a record to include it."
        ),
    }
