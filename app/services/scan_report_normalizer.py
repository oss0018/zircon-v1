"""
Normalized scan report model for Watchlist "Check Now" UI rendering.

Maps provider-specific OSINT API responses into a stable NormalizedScanReport
structure suitable for the right-side drawer visualization.

Currently supported providers:
  - urlscan  (search results + scan submission responses)

Adding a new provider:
  1. Implement `_normalize_<provider>(raw, base) -> dict`.
  2. Register it in the `_NORMALIZERS` dispatch table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _make_base(source: str, target: str, target_type: str, checked_at: str) -> dict:
    return {
        "source": source,
        "target": target,
        "target_type": target_type,
        "checked_at": checked_at,
        "status": "success",
        "verdict": None,
        "verdict_score": None,
        "main_ip": None,
        "asn": None,
        "org": None,
        "country": None,
        "final_url": None,
        "title": None,
        "tags": [],
        "scan_age": None,
        "provider_url": None,
        "screenshot_url": None,
        "indicators": None,
        "http_info": None,
        "dns_info": None,
        "links": None,
        "total_results": 0,
    }


def _canonical_source(source: str) -> str:
    s = (source or "").strip().lower()
    aliases = {
        "urlscan.io": "urlscan",
    }
    return aliases.get(s, s)


def _has_summary_data(report: dict | None) -> bool:
    if not isinstance(report, dict):
        return False
    if report.get("status") and report.get("status") != "success":
        return True
    key_fields = (
        "main_ip", "asn", "org", "country", "final_url", "title",
        "scan_age", "provider_url", "screenshot_url", "multi_scan_summary",
    )
    if any(report.get(k) for k in key_fields):
        return True
    if report.get("http_info") or report.get("dns_info"):
        return True
    if report.get("indicators"):
        return True
    if report.get("tags"):
        return True
    return bool(report.get("total_results"))


# ---------------------------------------------------------------------------
# urlscan.io normalizer
# ---------------------------------------------------------------------------

def _normalize_urlscan(raw: dict, base: dict) -> dict:
    """Normalize a urlscan.io API response (search or scan-submission)."""

    # --- Scan submission response ----------------------------------------
    # POST /api/v1/scan/ returns {"message": "...", "uuid": "...", "result": "..."}
    if "uuid" in raw and "message" in raw:
        base["status"] = "pending"
        base["provider_url"] = _safe_str(raw.get("result"))
        return base

    # --- Error / rate-limit ------------------------------------------------
    if "error" in raw:
        err = str(raw["error"]).lower()
        if "rate" in err or "429" in err:
            base["status"] = "rate_limited"
        else:
            base["status"] = "failed"
        return base

    if raw.get("not_found"):
        base["status"] = "no_data"
        return base

    # --- Search results ----------------------------------------------------
    results: list[dict] = raw.get("results") or []
    base["total_results"] = int(raw.get("total") or len(results))

    if not results:
        base["status"] = "no_data"
        return base

    # Use the first (most-recent) result
    r = results[0]
    page: dict = r.get("page") or {}
    task: dict = r.get("task") or {}
    verdicts: dict = r.get("verdicts") or {}
    overall: dict = verdicts.get("overall") or {}
    stats: dict = r.get("stats") or {}

    base["main_ip"] = _safe_str(page.get("ip"))
    base["asn"] = _safe_str(page.get("asn"))
    base["org"] = _safe_str(page.get("asnname"))
    base["country"] = _safe_str(page.get("country"))
    base["final_url"] = _safe_str(page.get("url")) or _safe_str(task.get("url"))
    base["title"] = _safe_str(page.get("title"))
    base["scan_age"] = _safe_str(task.get("time"))
    base["provider_url"] = (
        _safe_str(r.get("result"))
        or _safe_str(task.get("reportURL"))
    )
    base["screenshot_url"] = _safe_str(r.get("screenshot"))

    # Verdict
    is_malicious = bool(overall.get("malicious"))
    score = int(overall.get("score") or 0)
    base["verdict_score"] = score
    if is_malicious or score >= 70:
        base["verdict"] = "malicious"
    elif score >= 30:
        base["verdict"] = "suspicious"
    else:
        base["verdict"] = "clean"

    # Tags: categories + tags + brand names from verdict
    tag_set: set[str] = set()
    for t in (overall.get("categories") or []):
        tag_set.add(str(t))
    for t in (overall.get("tags") or []):
        tag_set.add(str(t))
    for t in (overall.get("brands") or []):
        tag_set.add(t.get("name", "") if isinstance(t, dict) else str(t))
    base["tags"] = sorted(x for x in tag_set if x)

    # HTTP info
    http_status = _safe_str(page.get("status"))
    server = _safe_str(page.get("server"))
    mime = _safe_str(page.get("mimeType"))
    if any([http_status, server, mime, base["final_url"]]):
        base["http_info"] = {
            "status": http_status,
            "server": server,
            "mime_type": mime,
            "final_url": base["final_url"],
        }

    # DNS info
    ptr = _safe_str(page.get("ptr"))
    domain = _safe_str(page.get("domain"))
    apex = _safe_str(page.get("apexDomain"))
    if any([ptr, domain, apex]):
        base["dns_info"] = {
            "ptr": ptr,
            "domain": domain,
            "apex_domain": apex,
        }

    # Indicators (populated when verdict is malicious/suspicious)
    indicators: list[dict] = []
    if base["main_ip"] and base["verdict"] in ("malicious", "suspicious"):
        indicators.append({
            "type": "ip",
            "value": base["main_ip"],
            "context": f"Main IP for {base['final_url'] or base['target']}",
        })
    engines: dict = verdicts.get("engines") or {}
    engine_malicious = int(engines.get("malicious") or 0)
    engine_benign = int(engines.get("benign") or 0)
    if engine_malicious > 0:
        indicators.append({
            "type": "verdict",
            "value": f"{engine_malicious} malicious engine detection(s)",
            "context": f"{engine_benign} benign",
        })
    if indicators:
        base["indicators"] = indicators

    # Stats (request count etc.)
    if stats:
        base["stats"] = {
            "requests": int(stats.get("requests") or 0),
            "malicious": int(stats.get("malicious") or 0),
            "suspicious": int(stats.get("suspicious") or 0),
        }

    # Multi-scan summary when more than one result was returned
    if len(results) > 1:
        base["scan_count"] = len(results)
        mal_count = sum(
            1 for rx in results
            if bool((rx.get("verdicts") or {}).get("overall", {}).get("malicious"))
        )
        if mal_count:
            base["multi_scan_summary"] = (
                f"{mal_count}/{len(results)} scans flagged as malicious"
            )

    return base


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_NORMALIZERS: dict[str, Any] = {
    "urlscan": _normalize_urlscan,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_scan_report(
    source: str,
    raw: dict,
    target: str,
    target_type: str,
    checked_at: str | None = None,
) -> dict:
    """
    Return a NormalizedScanReport dict for the given provider response.

    Args:
        source:      Provider name (e.g. "urlscan").
        raw:         Raw API response dict.
        target:      The search value (domain / IP / keyword …).
        target_type: Type of the search value.
        checked_at:  ISO timestamp of the check; defaults to utcnow.

    Returns:
        A dict with a stable set of keys (see _make_base) ready for the
        frontend drawer component.
    """
    if checked_at is None:
        checked_at = _utcnow_iso()

    base = _make_base(source, target, target_type, checked_at)

    if not raw or not isinstance(raw, dict):
        base["status"] = "no_data"
        return base

    normalizer = _NORMALIZERS.get(_canonical_source(source))
    if normalizer is None:
        # Unknown provider — return success base (frontend falls back to raw)
        return base

    try:
        return normalizer(raw, base)
    except Exception:
        base["status"] = "failed"
        return base


def ensure_normalized_scan_report(
    source: str,
    raw: dict,
    target: str,
    target_type: str,
    checked_at: str | None = None,
    existing_normalized: dict | None = None,
) -> dict | None:
    """
    Ensure a scan report has usable normalized data.
    Falls back to deriving normalized fields from raw payload on-the-fly.
    """
    if _has_summary_data(existing_normalized):
        return existing_normalized

    derived = normalize_scan_report(
        source=source,
        raw=raw,
        target=target,
        target_type=target_type,
        checked_at=checked_at,
    )
    if _has_summary_data(derived):
        return derived
    return existing_normalized or derived
