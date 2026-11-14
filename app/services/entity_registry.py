"""Adapters and comparison helpers for legal-entity registry lookups."""
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import quote

import httpx


COMPANIES_HOUSE_API = "https://api.company-information.service.gov.uk"
COMPANIES_HOUSE_PUBLIC = "https://find-and-update.company-information.service.gov.uk"
DELAWARE_ENTITY_SEARCH = "https://icis.corp.delaware.gov/Ecorp/EntitySearch/NameSearch.aspx"


class RegistryLookupError(Exception):
    """A registry request failed or returned an unusable response."""


class CompaniesHouseClient:
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def lookup(self, query: str | None, company_number: str | None) -> list[dict]:
        if company_number:
            path = f"/company/{quote(company_number, safe='')}"
            params = None
        else:
            path = "/search/companies"
            params = {"q": query or "", "items_per_page": 5}

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                response = await client.get(
                    f"{COMPANIES_HOUSE_API}{path}",
                    params=params,
                    auth=(self.api_key, ""),
                )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return []
            raise RegistryLookupError(
                f"Companies House returned HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise RegistryLookupError("Could not connect to Companies House") from exc
        except ValueError as exc:
            raise RegistryLookupError("Companies House returned invalid JSON") from exc

        if not isinstance(payload, dict):
            raise RegistryLookupError("Companies House returned an unexpected response")

        retrieved_at = datetime.now(timezone.utc).isoformat()
        if company_number:
            return [self._map_company(payload, retrieved_at)]
        items = payload.get("items")
        if not isinstance(items, list):
            raise RegistryLookupError("Companies House response did not contain company results")
        return [
            self._map_company(item, retrieved_at)
            for item in items[:5]
            if isinstance(item, dict)
        ]

    @staticmethod
    def _map_company(company: dict, retrieved_at: str) -> dict:
        number = company.get("company_number")
        return {
            "jurisdiction": "GB",
            "source": "Companies House",
            "source_type": "official_registry",
            "name": company.get("company_name"),
            "company_number": number,
            "status": company.get("company_status"),
            "company_type": company.get("type"),
            "incorporated_on": company.get("date_of_creation"),
            "registered_address": _format_address(company.get("registered_office_address")),
            "source_url": (
                f"{COMPANIES_HOUSE_PUBLIC}/company/{quote(str(number), safe='')}"
                if number else None
            ),
            "retrieved_at": retrieved_at,
        }


def _format_address(address: object) -> str | None:
    if not isinstance(address, dict):
        return None
    values = [
        str(value).strip()
        for value in address.values()
        if isinstance(value, str) and value.strip()
    ]
    return ", ".join(values) or None


def build_comparison(
    uk_companies: list[dict],
    delaware_record: dict | None,
    query: str | None,
    delaware_search_query: str | None = None,
) -> dict:
    delaware = None
    comparisons = []
    if delaware_record:
        delaware = {
            "jurisdiction": "US-DE",
            "source": "Delaware Division of Corporations",
            "source_type": "user_supplied",
            "name": delaware_record.get("name"),
            "company_number": delaware_record.get("entity_number"),
            "status": delaware_record.get("status"),
            "incorporated_on": delaware_record.get("incorporated_on"),
            "registered_address": delaware_record.get("registered_address"),
            "source_url": DELAWARE_ENTITY_SEARCH,
            "retrieved_at": None,
        }
        for company in uk_companies:
            score = _name_similarity(delaware.get("name"), company.get("name"))
            comparisons.append({
                "uk_company_number": company.get("company_number"),
                "uk_company_name": company.get("name"),
                "name_similarity": score,
                "interpretation": _interpret_similarity(score),
            })

    return {
        "query": query,
        "uk_results": uk_companies,
        "delaware_record": delaware,
        "delaware_search_url": DELAWARE_ENTITY_SEARCH,
        "delaware_search_query": delaware_search_query or query,
        "delaware_record_notice": (
            "Delaware details are user-provided and have not been verified against the registry."
            if delaware else
            "Delaware registry lookup is not automated; use the official search and provide a record to compare."
        ),
        "comparisons": comparisons,
        "comparison_notice": (
            "Name similarity is a triage signal, not proof that records identify the same legal entity."
        ),
    }


def _name_similarity(left: str | None, right: str | None) -> int | None:
    if not left or not right:
        return None
    normalized_left = " ".join(left.casefold().split())
    normalized_right = " ".join(right.casefold().split())
    return round(SequenceMatcher(None, normalized_left, normalized_right).ratio() * 100)


def _interpret_similarity(score: int | None) -> str:
    if score is None:
        return "not_comparable"
    if score >= 90:
        return "strong_textual_similarity"
    if score >= 70:
        return "possible_textual_similarity"
    return "low_textual_similarity"
