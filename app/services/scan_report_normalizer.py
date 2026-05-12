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
        "have_i_been_pwned": "hibp",
        "otx": "alienvault",
        "intelligencex": "intelx",
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

def _normalize_virustotal(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if raw.get("not_found"): base["status"] = "no_data"; return base
    # v2
    if "positives" in raw:
        pos = int(raw.get("positives", 0)); total = int(raw.get("total", 1) or 1)
        base["verdict"] = "malicious" if pos >= 10 else ("suspicious" if pos >= 1 else "clean")
        base["verdict_score"] = round(pos / total * 100); base["total_results"] = pos
        base["provider_url"] = _safe_str(raw.get("permalink")); base["scan_age"] = _safe_str(raw.get("scan_date"))
        detected = [(e, v["result"]) for e, v in (raw.get("scans") or {}).items() if v.get("detected")]
        if detected: base["indicators"] = [{"type": "detection", "value": f"{e}: {r}", "context": "Engine"} for e, r in detected[:15]]
        return base
    # v3
    data_obj = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}
    attrs = data_obj.get("attributes", {}) or raw.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}); mal = int(stats.get("malicious", 0)); sus = int(stats.get("suspicious", 0)); total = sum(stats.values()) if stats else 0
    base["verdict"] = "malicious" if mal > 0 else ("suspicious" if sus > 0 else "clean")
    base["verdict_score"] = round(mal / total * 100) if total else 0; base["total_results"] = mal + sus
    base["title"] = _safe_str(attrs.get("meaningful_name")); base["tags"] = list(attrs.get("tags", []))[:6]
    results = attrs.get("last_analysis_results", {})
    det = [{"type": "detection", "value": f"{e}: {v.get('result', '')}", "context": v.get("category", "")} for e, v in results.items() if v and v.get("category") in ("malicious", "suspicious")][:15]
    if det: base["indicators"] = det
    return base


def _normalize_abuseipdb(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    data = raw.get("data", raw) or {}
    score = int(data.get("abuseConfidenceScore") or data.get("abuse_confidence_score") or 0)
    base["verdict_score"] = score; base["verdict"] = "malicious" if score >= 75 else ("suspicious" if score >= 25 else "clean")
    base["total_results"] = int(data.get("totalReports") or data.get("total_reports") or 0)
    country = _safe_str(data.get("countryName") or data.get("country_name")); code = _safe_str(data.get("countryCode") or data.get("country_code"))
    base["country"] = f"{country} ({code})" if country and code else (country or code)
    base["asn"] = _safe_str(data.get("isp")); base["main_ip"] = _safe_str(data.get("ipAddress") or data.get("ip_address"))
    base["scan_age"] = _safe_str(data.get("lastReportedAt") or data.get("last_reported_at"))
    reports = (data.get("reports") or [])[:5]
    if reports: base["indicators"] = [{"type": "report", "value": (r.get("comment") or "Abuse report")[:100], "context": r.get("reportedAt", "")} for r in reports]
    return base


def _normalize_shodan(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if not raw or raw.get("not_found"): base["status"] = "no_data"; return base
    base["main_ip"] = _safe_str(raw.get("ip_str") or raw.get("ip")); base["org"] = _safe_str(raw.get("org"))
    base["asn"] = _safe_str(raw.get("asn")); base["scan_age"] = _safe_str(raw.get("last_update"))
    base["country"] = ", ".join(filter(None, [raw.get("country_name", ""), raw.get("city", "")])) or None
    ports = raw.get("ports", []); base["total_results"] = len(ports)
    inds = [{"type": "port", "value": str(p), "context": "Open port"} for p in ports[:20]]
    vulns = raw.get("vulns", {})
    if vulns: inds += [{"type": "cve", "value": cve, "context": "Vulnerability"} for cve in list(vulns.keys())[:10]]; base["verdict"] = "suspicious"
    base["indicators"] = inds or None
    services = raw.get("data", []); base["tags"] = list({s.get("product") for s in services if s.get("product")})[:5]
    return base


def _normalize_hibp(raw: dict, base: dict) -> dict:
    if isinstance(raw, dict) and raw.get("error"): base["status"] = "failed"; return base
    breaches = raw if isinstance(raw, list) else raw.get("breaches", [])
    if not breaches: base["verdict"] = "clean"; base["total_results"] = 0; return base
    base["total_results"] = len(breaches); base["verdict"] = "malicious" if len(breaches) >= 5 else "suspicious"
    base["verdict_score"] = min(100, len(breaches) * 10)
    base["indicators"] = [{"type": "breach", "value": (b.get("Name") or b.get("name") or "Unknown")[:60], "context": b.get("BreachDate") or b.get("breach_date") or ""} for b in breaches[:10]]
    all_dc = [dc for b in breaches[:5] for dc in (b.get("DataClasses") or b.get("data_classes") or [])]
    base["tags"] = list(dict.fromkeys(all_dc))[:8]
    return base


def _normalize_alienvault(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if not raw: base["status"] = "no_data"; return base
    pi = raw.get("pulse_info", {}); pc = int(pi.get("count") or raw.get("pulse_count") or 0)
    base["total_results"] = pc; base["verdict"] = "malicious" if pc >= 10 else ("suspicious" if pc >= 2 else "clean")
    base["verdict_score"] = min(100, pc * 5); base["country"] = _safe_str(raw.get("country_name")); base["asn"] = _safe_str(raw.get("asn"))
    pulses = (pi.get("pulses") or [])[:5]
    if pulses: base["indicators"] = [{"type": "pulse", "value": p.get("name", "Pulse")[:60], "context": p.get("tlp", "")} for p in pulses]
    return base


def _normalize_intelx(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    records = raw.get("records", []); total = int(raw.get("total") or len(records))
    base["total_results"] = total
    if not total: base["status"] = "no_data"; return base
    base["verdict"] = "suspicious"
    if records:
        base["indicators"] = [{"type": str(r.get("type", "record")), "value": (r.get("name") or "")[:80], "context": r.get("date", "")} for r in records[:10]]
        base["tags"] = list({r.get("bucket", "") for r in records if r.get("bucket")})[:6]
    return base


def _normalize_urlhaus(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    qs = raw.get("query_status", "")
    if qs in ("no_results", "is_not_malware"): base["verdict"] = "clean"; return base
    if not raw or raw.get("not_found"): base["status"] = "no_data"; return base
    base["verdict"] = "malicious" if qs == "is_malware" else "suspicious"; base["verdict_score"] = 100 if qs == "is_malware" else 50
    threat = _safe_str(raw.get("threat")); base["tags"] = ([threat] if threat else []) + list(raw.get("tags") or [])[:5]
    urls = raw.get("urls", []); base["total_results"] = len(urls); base["provider_url"] = _safe_str(raw.get("urlhaus_reference"))
    if urls: base["indicators"] = [{"type": "url", "value": (u.get("url") or "")[:80], "context": u.get("url_status", "")} for u in urls[:10]]
    return base


def _normalize_phishtank(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    results = raw.get("results", raw); in_db = results.get("in_database", False)
    if not in_db: base["verdict"] = "clean"; base["total_results"] = 0; return base
    valid = results.get("valid", False)
    base["verdict"] = "malicious" if valid else "suspicious"; base["verdict_score"] = 100 if valid else 50
    base["total_results"] = 1; base["provider_url"] = _safe_str(results.get("phish_detail_page"))
    base["indicators"] = [{"type": "phish", "value": "Confirmed phishing" if valid else "In PhishTank database", "context": "PhishTank"}]
    return base


def _normalize_securitytrails(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if not raw: base["status"] = "no_data"; return base
    dns = raw.get("current_dns", {}); records = []
    for rtype in ("a", "aaaa", "mx", "ns", "txt", "cname"):
        for v in (dns.get(rtype) or {}).get("values", [])[:3]:
            val = v.get("ip") or v.get("hostname") or v.get("nameserver") or v.get("value") or str(v)
            records.append({"type": rtype.upper(), "value": str(val)[:80], "context": "DNS"})
    base["total_results"] = len(records); base["indicators"] = records[:15] or None
    base["title"] = _safe_str(raw.get("hostname")); base["verdict"] = "clean"
    whois = raw.get("whois") or {}
    base["org"] = _safe_str(whois.get("registrar")) if isinstance(whois, dict) else None
    return base


def _normalize_censys(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if not raw: base["status"] = "no_data"; return base
    data = raw.get("result", raw); base["main_ip"] = _safe_str(data.get("ip"))
    loc = data.get("location") or {}; base["country"] = _safe_str(loc.get("country"))
    asn_d = data.get("autonomous_system") or {}
    base["asn"] = f"AS{asn_d.get('asn', '')} {asn_d.get('name', '')}".strip() if asn_d else None
    services = data.get("services", []); base["total_results"] = len(services)
    if services:
        base["indicators"] = [{"type": "service", "value": f"{s.get('port')}/{(s.get('transport_protocol') or '').lower()}", "context": s.get("service_name", "")} for s in services[:15]]
        base["tags"] = list({s.get("service_name") for s in services if s.get("service_name") and s["service_name"] != "UNKNOWN"})[:6]
    base["verdict"] = "clean"; return base


def _normalize_malwarebazaar(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if raw.get("query_status") == "hash_not_found": base["status"] = "no_data"; base["verdict"] = "clean"; return base
    samples = raw.get("data", [])
    if not samples: base["status"] = "no_data"; return base
    s = samples[0]; base["verdict"] = "malicious"; base["verdict_score"] = 100; base["total_results"] = len(samples)
    base["title"] = _safe_str(s.get("file_name")); base["tags"] = (s.get("tags") or [])[:6]; base["scan_age"] = _safe_str(s.get("first_seen"))
    inds = []
    if s.get("signature"): inds.append({"type": "malware", "value": s["signature"], "context": "Malware family"})
    if s.get("sha256_hash"): inds.append({"type": "hash", "value": s["sha256_hash"], "context": "SHA-256"})
    if s.get("file_type"): inds.append({"type": "filetype", "value": s["file_type"], "context": "File type"})
    base["indicators"] = inds or None; return base


def _normalize_threatfox(raw: dict, base: dict) -> dict:
    if raw.get("error"): base["status"] = "failed"; return base
    if raw.get("query_status") == "no_result": base["status"] = "no_data"; base["verdict"] = "clean"; return base
    iocs = raw.get("data", [])
    if not iocs: base["status"] = "no_data"; return base
    first = iocs[0]; base["verdict"] = "malicious"; base["verdict_score"] = int(first.get("confidence_level") or 75)
    base["total_results"] = len(iocs); base["scan_age"] = _safe_str(first.get("first_seen"))
    inds = []
    if first.get("malware"): inds.append({"type": "malware", "value": first["malware"], "context": _safe_str(first.get("malware_alias")) or ""})
    if first.get("ioc_type") and first.get("ioc"): inds.append({"type": first["ioc_type"], "value": first["ioc"], "context": "IOC"})
    base["indicators"] = inds or None
    base["tags"] = list({tag for ioc in iocs for tag in (ioc.get("tags") or [])})[:6]
    return base


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_NORMALIZERS: dict[str, Any] = {
    "urlscan": _normalize_urlscan,
    "urlscan.io": _normalize_urlscan,
    "virustotal": _normalize_virustotal,
    "abuseipdb": _normalize_abuseipdb,
    "shodan": _normalize_shodan,
    "hibp": _normalize_hibp,
    "have_i_been_pwned": _normalize_hibp,
    "alienvault": _normalize_alienvault,
    "otx": _normalize_alienvault,
    "intelx": _normalize_intelx,
    "intelligencex": _normalize_intelx,
    "urlhaus": _normalize_urlhaus,
    "phishtank": _normalize_phishtank,
    "securitytrails": _normalize_securitytrails,
    "censys": _normalize_censys,
    "malwarebazaar": _normalize_malwarebazaar,
    "threatfox": _normalize_threatfox,
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
