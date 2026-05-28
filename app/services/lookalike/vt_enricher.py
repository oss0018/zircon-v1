"""
VirusTotal enrichment — Look-alike Domains.

Uses VirusTotal API v3 domain lookup via VirusTotalClient.
Returns a dict with standardised fields; all values are None on any error so
callers can treat the result unconditionally.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.services.osint.virustotal import VirusTotalClient

logger = logging.getLogger(__name__)


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _null_result() -> dict:
    return {
        "vt_malicious": None,
        "vt_suspicious": None,
        "vt_harmless": None,
        "vt_undetected": None,
        "vt_engines": None,
        "vt_community_score": None,
        "vt_last_analysis_date": None,
    }


async def enrich_vt(domain: str, api_key: str) -> dict:
    """
    Async VirusTotal enrichment for *domain*.

    Returns VT stats + metadata for the domain. All values are None when the
    key is absent or the request/parse fails.
    """
    if not api_key:
        return _null_result()

    try:
        client = VirusTotalClient(api_key=api_key)
        result = await client.search(domain, query_type="domain")

        data = (result or {}).get("data")
        if not isinstance(data, dict):
            return _null_result()
        attrs = data.get("attributes")
        if not isinstance(attrs, dict):
            return _null_result()
        stats = attrs.get("last_analysis_stats")
        if not isinstance(stats, dict):
            return _null_result()

        analysis_results = attrs.get("last_analysis_results") or {}
        engines = []
        if isinstance(analysis_results, dict):
            for engine_name, engine_data in analysis_results.items():
                if not isinstance(engine_data, dict):
                    continue
                category = engine_data.get("category")
                if category in {"malicious", "suspicious"}:
                    engines.append(str(engine_name))
                    if len(engines) >= 10:
                        break

        total_votes = attrs.get("total_votes") or {}
        community_score = None
        if isinstance(total_votes, dict):
            harmless_votes = total_votes.get("harmless")
            malicious_votes = total_votes.get("malicious")
            if isinstance(harmless_votes, int) and isinstance(malicious_votes, int):
                community_score = malicious_votes - harmless_votes

        last_analysis_date = attrs.get("last_analysis_date")
        last_analysis_dt = None
        if isinstance(last_analysis_date, (int, float)):
            last_analysis_dt = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc)

        return {
            "vt_malicious": _as_int(stats.get("malicious"), 0),
            "vt_suspicious": _as_int(stats.get("suspicious"), 0),
            "vt_harmless": _as_int(stats.get("harmless"), 0),
            "vt_undetected": _as_int(stats.get("undetected"), 0),
            "vt_engines": json.dumps(engines),
            "vt_community_score": community_score,
            "vt_last_analysis_date": last_analysis_dt,
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("VirusTotal enrichment failed for %s: %s", domain, exc)
        return _null_result()
