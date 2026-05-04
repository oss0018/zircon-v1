"""
Threat Intelligence result normalizer.

Converts raw API responses from each connector into a unified, human-readable schema:

{
    "verdict":      "malicious" | "suspicious" | "clean" | "unknown",
    "severity":     "critical" | "high" | "medium" | "low" | "none",
    "confidence":   0-100  (int),
    "tags":         [...],
    "sources_hit":  [...],          # sources that found something
    "detections": [                 # engine/provider detection list
        {"engine": "...", "result": "...", "category": "..."}
    ],
    "enrichment": {
        "geo":      {"country": ..., "city": ..., "asn": ..., "isp": ...},
        "whois":    {...},
        "dns":      {...},
        "network":  {"ports": [...], "protocols": [...]},
    },
    "artifacts": {
        "ips":      [...],
        "domains":  [...],
        "urls":     [...],
        "hashes":   [...],
        "emails":   [...],
    },
    "timeline":     [{"date": ..., "event": ..., "source": ...}],
    "summary":      "Short human-readable summary string",
    "raw":          {source: raw_data, ...},
}
"""
from __future__ import annotations
from typing import Any


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def normalize(ioc: str, ioc_type: str, source_results: dict[str, Any]) -> dict:
    """
    Build a unified normalized result from a dict of {service_type: raw_data}.
    Returns the unified schema dict.
    """
    result: dict = {
        "verdict": "unknown",
        "severity": "none",
        "confidence": 0,
        "tags": [],
        "sources_hit": [],
        "detections": [],
        "enrichment": {
            "geo": {},
            "whois": {},
            "dns": {},
            "network": {},
        },
        "artifacts": {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": [],
        },
        "timeline": [],
        "summary": "",
        "raw": {},
    }

    per_source_verdicts: list[tuple[str, str, int]] = []  # (source, verdict, score)

    for source, raw in source_results.items():
        result["raw"][source] = raw
        if not raw or not isinstance(raw, dict):
            continue
        if raw.get("error") or raw.get("not_found"):
            continue

        adapter = _ADAPTERS.get(source)
        if adapter:
            partial = adapter(raw, ioc_type)
            _merge_partial(result, partial, source)
            if partial.get("verdict") and partial["verdict"] != "unknown":
                per_source_verdicts.append((source, partial["verdict"], partial.get("confidence", 0)))

    # Aggregate verdict / severity from all sources
    result["verdict"], result["severity"], result["confidence"] = _aggregate_verdict(per_source_verdicts)

    # De-duplicate lists
    for key in result["tags"]:
        pass  # already strings
    result["tags"] = _dedup(result["tags"])
    for k in result["artifacts"]:
        result["artifacts"][k] = _dedup(result["artifacts"][k])
    result["detections"] = _dedup_dicts(result["detections"], "engine")

    # Build summary text
    result["summary"] = _build_summary(ioc, ioc_type, result)

    return result


# ---------------------------------------------------------------------------
# Merge helper
# ---------------------------------------------------------------------------

def _merge_partial(result: dict, partial: dict, source: str):
    if partial.get("sources_hit"):
        result["sources_hit"].extend(partial["sources_hit"])
    if partial.get("tags"):
        result["tags"].extend(partial["tags"])
    if partial.get("detections"):
        result["detections"].extend(partial["detections"])
    if partial.get("timeline"):
        result["timeline"].extend(partial["timeline"])

    # Enrichment
    for section in ("geo", "whois", "dns", "network"):
        if partial.get("enrichment", {}).get(section):
            if not result["enrichment"][section]:
                result["enrichment"][section] = partial["enrichment"][section]
            else:
                result["enrichment"][section].update(partial["enrichment"][section])

    # Artifacts
    for art_key in result["artifacts"]:
        if partial.get("artifacts", {}).get(art_key):
            result["artifacts"][art_key].extend(partial["artifacts"][art_key])


# ---------------------------------------------------------------------------
# Verdict aggregation
# ---------------------------------------------------------------------------

_VERDICT_ORDER = {"malicious": 4, "suspicious": 3, "clean": 1, "unknown": 0}
_SEVERITY_MAP = {
    "malicious": {"high": "critical", "medium": "high", "low": "high"},
    "suspicious": {"high": "high", "medium": "medium", "low": "medium"},
    "clean": {"high": "none", "medium": "none", "low": "none"},
    "unknown": {"high": "none", "medium": "none", "low": "none"},
}


def _aggregate_verdict(verdicts: list[tuple[str, str, int]]) -> tuple[str, str, int]:
    if not verdicts:
        return "unknown", "none", 0

    # Highest-priority verdict wins
    best_verdict = "unknown"
    max_confidence = 0
    for _src, verdict, conf in verdicts:
        if _VERDICT_ORDER.get(verdict, 0) > _VERDICT_ORDER.get(best_verdict, 0):
            best_verdict = verdict
            max_confidence = conf
        elif _VERDICT_ORDER.get(verdict, 0) == _VERDICT_ORDER.get(best_verdict, 0):
            if conf > max_confidence:
                max_confidence = conf

    # Derive severity from verdict + confidence
    if best_verdict == "malicious":
        if max_confidence >= 75:
            severity = "critical"
        elif max_confidence >= 40:
            severity = "high"
        else:
            severity = "medium"
    elif best_verdict == "suspicious":
        if max_confidence >= 60:
            severity = "high"
        elif max_confidence >= 30:
            severity = "medium"
        else:
            severity = "low"
    elif best_verdict == "clean":
        severity = "none"
    else:
        severity = "none"

    return best_verdict, severity, max_confidence


# ---------------------------------------------------------------------------
# Per-source adapters
# ---------------------------------------------------------------------------

def _adapt_virustotal(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    # VT v2 style (legacy endpoint returns positives/total at root)
    positives = raw.get("positives")
    total = raw.get("total")
    if positives is not None and total is not None:
        pct = int(positives / total * 100) if total > 0 else 0
        partial["confidence"] = pct
        if positives >= 10:
            partial["verdict"] = "malicious"
        elif positives >= 3:
            partial["verdict"] = "suspicious"
        elif positives == 0:
            partial["verdict"] = "clean"
        if positives > 0:
            partial["sources_hit"].append("VirusTotal")
        scans = raw.get("scans", {})
        for engine, info in scans.items():
            if info and info.get("detected"):
                partial["detections"].append({
                    "engine": engine,
                    "result": info.get("result", "malicious"),
                    "category": "antivirus",
                })
        return partial

    # VT v3 style (data.attributes)
    attrs = raw.get("data", {}).get("attributes", {}) or raw.get("attributes", {})
    if not attrs:
        return partial

    stats = attrs.get("last_analysis_stats", {})
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total_v3 = sum(stats.values()) if stats else 0
    hits = mal + sus
    pct = int(hits / total_v3 * 100) if total_v3 > 0 else 0
    partial["confidence"] = pct

    if mal >= 10:
        partial["verdict"] = "malicious"
    elif mal >= 3 or sus >= 5:
        partial["verdict"] = "suspicious"
    elif hits == 0:
        partial["verdict"] = "clean"

    if hits > 0:
        partial["sources_hit"].append("VirusTotal")

    # Tags
    partial["tags"].extend(attrs.get("tags", []) or [])
    cats = attrs.get("popular_threat_classification", {})
    if cats:
        for c in (cats.get("popular_threat_name") or []):
            partial["tags"].append(c.get("value", ""))

    # Detections
    last_results = attrs.get("last_analysis_results", {})
    for engine, info in last_results.items():
        if info and info.get("category") in ("malicious", "suspicious"):
            partial["detections"].append({
                "engine": engine,
                "result": info.get("result", info.get("category", "")),
                "category": info.get("category", ""),
            })

    # Enrichment: geo for IP
    if ioc_type == "ip":
        partial["enrichment"]["geo"] = {
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", ""),
            "network": attrs.get("network", ""),
        }

    # Enrichment: DNS for domain
    if ioc_type == "domain":
        dns: dict = {}
        if attrs.get("last_dns_records"):
            dns["records"] = [
                {"type": r.get("type", ""), "value": r.get("value", "")}
                for r in attrs.get("last_dns_records", [])[:10]
            ]
        partial["enrichment"]["dns"] = dns
        # Related IPs from resolutions
        for rec in (attrs.get("last_dns_records") or []):
            v = rec.get("value", "")
            if rec.get("type") == "A" and v:
                partial["artifacts"]["ips"].append(v)

    # Artifacts: URLs from URL analysis
    if attrs.get("url"):
        partial["artifacts"]["urls"].append(attrs["url"])

    return partial


def _adapt_abuseipdb(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    data = raw.get("data", raw)
    score = data.get("abuse_confidence_score", 0)
    if score is None:
        score = 0
    partial["confidence"] = score
    if score >= 75:
        partial["verdict"] = "malicious"
    elif score >= 25:
        partial["verdict"] = "suspicious"
    elif score == 0 and "ipAddress" in data:
        partial["verdict"] = "clean"

    if score > 0:
        partial["sources_hit"].append("AbuseIPDB")

    partial["enrichment"]["geo"] = {
        "country": data.get("countryName", data.get("country_name", "")),
        "country_code": data.get("countryCode", data.get("country_code", "")),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "usage_type": data.get("usageType", data.get("usage_type", "")),
    }

    reports = data.get("totalReports", data.get("total_reports", 0)) or 0
    if reports > 0:
        partial["detections"].append({
            "engine": "AbuseIPDB",
            "result": f"{reports} abuse reports",
            "category": "abuse",
        })
        # Recent report categories as tags
        for rep in (data.get("reports") or [])[:5]:
            for cat in (rep.get("categories") or []):
                partial["tags"].append(str(cat))

    return partial


def _adapt_alienvault(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    pulse_count = raw.get("pulse_info", {}).get("count", raw.get("pulse_count", 0)) or 0
    partial["confidence"] = min(int(pulse_count * 5), 100)
    if pulse_count >= 10:
        partial["verdict"] = "malicious"
    elif pulse_count >= 3:
        partial["verdict"] = "suspicious"
    elif pulse_count == 0:
        partial["verdict"] = "clean"

    if pulse_count > 0:
        partial["sources_hit"].append("AlienVault OTX")

    # Tags from pulses
    pulse_info = raw.get("pulse_info", {})
    for pulse in (pulse_info.get("pulses") or [])[:10]:
        for tag in (pulse.get("tags") or []):
            partial["tags"].append(tag)
        for malware in (pulse.get("malware_families") or []):
            partial["tags"].append(malware.get("display_name", "") or malware)

    # Geo
    partial["enrichment"]["geo"] = {
        "country": raw.get("country_name", ""),
        "country_code": raw.get("country_code", ""),
        "city": raw.get("city", ""),
        "asn": raw.get("asn", ""),
        "latitude": raw.get("latitude", ""),
        "longitude": raw.get("longitude", ""),
    }

    # Artifacts
    for rel in (raw.get("related") or []):
        rtype = rel.get("type", "")
        rval = rel.get("indicator", "")
        if rtype == "IPv4" and rval:
            partial["artifacts"]["ips"].append(rval)
        elif rtype == "domain" and rval:
            partial["artifacts"]["domains"].append(rval)
        elif rtype == "URL" and rval:
            partial["artifacts"]["urls"].append(rval)
        elif rtype in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256") and rval:
            partial["artifacts"]["hashes"].append(rval)

    # Timeline from recent pulses
    for pulse in (pulse_info.get("pulses") or [])[:5]:
        partial["timeline"].append({
            "date": pulse.get("modified", ""),
            "event": f"Pulse: {pulse.get('name', '?')}",
            "source": "AlienVault OTX",
        })

    return partial


def _adapt_urlhaus(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    status = raw.get("query_status", "")
    if status == "is_malware":
        partial["verdict"] = "malicious"
        partial["confidence"] = 90
        partial["sources_hit"].append("URLhaus")
    elif status == "no_results":
        partial["verdict"] = "clean"

    if raw.get("tags"):
        partial["tags"].extend(raw["tags"])
    if raw.get("threat"):
        partial["tags"].append(raw["threat"])
        partial["detections"].append({
            "engine": "URLhaus",
            "result": raw["threat"],
            "category": "malware_url",
        })

    for url_entry in (raw.get("urls") or [])[:10]:
        if url_entry.get("url"):
            partial["artifacts"]["urls"].append(url_entry["url"])
        if url_entry.get("tags"):
            partial["tags"].extend(url_entry["tags"])
        if url_entry.get("date_added"):
            partial["timeline"].append({
                "date": url_entry["date_added"],
                "event": f"Malicious URL submitted: {url_entry.get('url', '?')[:80]}",
                "source": "URLhaus",
            })

    return partial


def _adapt_phishtank(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    results = raw.get("results", {})
    if results.get("in_database"):
        if results.get("valid"):
            partial["verdict"] = "malicious"
            partial["confidence"] = 95
            partial["sources_hit"].append("PhishTank")
            partial["detections"].append({
                "engine": "PhishTank",
                "result": "Confirmed phishing",
                "category": "phishing",
            })
            partial["tags"].append("phishing")
    else:
        partial["verdict"] = "clean"

    if results.get("phish_submit_time"):
        partial["timeline"].append({
            "date": results["phish_submit_time"],
            "event": "Phishing URL submitted to PhishTank",
            "source": "PhishTank",
        })

    return partial


def _adapt_shodan(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    vulns = raw.get("vulns", {})
    ports = raw.get("ports", []) or []
    if vulns:
        partial["verdict"] = "suspicious"
        partial["confidence"] = min(len(vulns) * 15, 90)
        partial["sources_hit"].append("Shodan")
        for cve in list(vulns.keys())[:20]:
            partial["tags"].append(cve)
            partial["detections"].append({
                "engine": "Shodan",
                "result": cve,
                "category": "vulnerability",
            })

    partial["enrichment"]["geo"] = {
        "country": raw.get("country_name", ""),
        "country_code": raw.get("country_code", ""),
        "city": raw.get("city", ""),
        "asn": raw.get("asn", ""),
        "org": raw.get("org", ""),
        "isp": raw.get("isp", ""),
    }
    partial["enrichment"]["network"] = {
        "ports": ports[:30],
        "os": raw.get("os", ""),
        "hostnames": raw.get("hostnames", [])[:10],
    }

    for hostname in (raw.get("hostnames") or [])[:10]:
        partial["artifacts"]["domains"].append(hostname)

    return partial


def _adapt_malwarebazaar(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    query_status = raw.get("query_status", "")
    if query_status in ("ok",):
        data_list = raw.get("data", []) or []
        if data_list:
            partial["verdict"] = "malicious"
            partial["confidence"] = 95
            partial["sources_hit"].append("MalwareBazaar")
            sample = data_list[0] if isinstance(data_list, list) else data_list
            if isinstance(sample, dict):
                for tag in (sample.get("tags") or []):
                    partial["tags"].append(tag)
                if sample.get("signature"):
                    partial["tags"].append(sample["signature"])
                partial["detections"].append({
                    "engine": "MalwareBazaar",
                    "result": sample.get("signature", "malware"),
                    "category": "malware",
                })
                # Hashes
                for h in ("md5_hash", "sha1_hash", "sha256_hash"):
                    v = sample.get(h)
                    if v:
                        partial["artifacts"]["hashes"].append(v)
                if sample.get("first_seen"):
                    partial["timeline"].append({
                        "date": sample["first_seen"],
                        "event": f"Malware first seen: {sample.get('signature', '?')}",
                        "source": "MalwareBazaar",
                    })
    elif query_status == "hash_not_found":
        partial["verdict"] = "clean"

    return partial


def _adapt_threatfox(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    query_status = raw.get("query_status", "")
    if query_status in ("ok",):
        data_list = raw.get("data", []) or []
        if data_list:
            partial["verdict"] = "malicious"
            partial["confidence"] = 90
            partial["sources_hit"].append("ThreatFox")
            for ioc_entry in (data_list if isinstance(data_list, list) else [data_list])[:10]:
                if not isinstance(ioc_entry, dict):
                    continue
                if ioc_entry.get("malware"):
                    partial["tags"].append(ioc_entry["malware"])
                if ioc_entry.get("tags"):
                    partial["tags"].extend(ioc_entry["tags"])
                partial["detections"].append({
                    "engine": "ThreatFox",
                    "result": ioc_entry.get("malware", "malware"),
                    "category": ioc_entry.get("ioc_type", "ioc"),
                })
                if ioc_entry.get("first_seen"):
                    partial["timeline"].append({
                        "date": ioc_entry["first_seen"],
                        "event": f"IOC added to ThreatFox: {ioc_entry.get('malware', '?')}",
                        "source": "ThreatFox",
                    })
    elif query_status == "no_result":
        partial["verdict"] = "clean"

    return partial


def _adapt_urlscan(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    results = raw.get("results", [])
    total = raw.get("total", 0)
    if total and results:
        partial["sources_hit"].append("urlscan.io")
        first = results[0]
        page = first.get("page", {}) or {}
        verdicts = first.get("verdicts", {}) or {}
        overall = verdicts.get("overall", {}) or {}
        if overall.get("malicious"):
            partial["verdict"] = "malicious"
            partial["confidence"] = min(overall.get("score", 50), 100)
        elif overall.get("score", 0) > 0:
            partial["verdict"] = "suspicious"
            partial["confidence"] = overall.get("score", 30)
        for cat in (overall.get("categories") or []):
            partial["tags"].append(cat)
        # Geo
        partial["enrichment"]["geo"] = {
            "country": page.get("country", ""),
            "city": page.get("city", ""),
            "asnname": page.get("asnname", ""),
            "asn": page.get("asn", ""),
        }
        if first.get("result"):
            partial["artifacts"]["urls"].append(first["result"])

    return partial


def _adapt_hibp(raw: dict, ioc_type: str) -> dict:
    partial: dict = {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }
    if isinstance(raw, list):
        if raw:
            partial["verdict"] = "suspicious"
            partial["confidence"] = min(len(raw) * 20, 90)
            partial["sources_hit"].append("Have I Been Pwned")
            for breach in raw[:10]:
                partial["detections"].append({
                    "engine": "HIBP",
                    "result": f"Breach: {breach.get('Name', breach.get('name', '?'))}",
                    "category": "data_breach",
                })
                partial["tags"].append(breach.get("Name", breach.get("name", "")))
                if breach.get("BreachDate") or breach.get("breach_date"):
                    partial["timeline"].append({
                        "date": breach.get("BreachDate") or breach.get("breach_date", ""),
                        "event": f"Data breach: {breach.get('Name', '?')}",
                        "source": "HIBP",
                    })
        else:
            partial["verdict"] = "clean"

    return partial


def _adapt_generic(raw: dict, ioc_type: str) -> dict:
    return {
        "sources_hit": [],
        "verdict": "unknown",
        "confidence": 0,
        "tags": [],
        "detections": [],
        "enrichment": {"geo": {}, "whois": {}, "dns": {}, "network": {}},
        "artifacts": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": []},
        "timeline": [],
    }


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------

_ADAPTERS = {
    "virustotal": _adapt_virustotal,
    "abuseipdb": _adapt_abuseipdb,
    "alienvault": _adapt_alienvault,
    "urlhaus": _adapt_urlhaus,
    "phishtank": _adapt_phishtank,
    "shodan": _adapt_shodan,
    "malwarebazaar": _adapt_malwarebazaar,
    "threatfox": _adapt_threatfox,
    "urlscan": _adapt_urlscan,
    "hibp": _adapt_hibp,
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _dedup(lst: list) -> list:
    seen: set = set()
    out = []
    for item in lst:
        v = str(item).strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _dedup_dicts(lst: list, key: str) -> list:
    seen: set = set()
    out = []
    for item in lst:
        k = item.get(key, "")
        if k not in seen:
            seen.add(k)
            out.append(item)
    return out


def _build_summary(ioc: str, ioc_type: str, result: dict) -> str:
    verdict = result["verdict"]
    severity = result["severity"]
    sources = result["sources_hit"]
    detections = result["detections"]
    tags = result["tags"][:5]

    parts = []
    if verdict == "malicious":
        parts.append(f"⚠️ {ioc} is flagged as MALICIOUS")
    elif verdict == "suspicious":
        parts.append(f"🔶 {ioc} is SUSPICIOUS")
    elif verdict == "clean":
        parts.append(f"✅ {ioc} appears CLEAN")
    else:
        parts.append(f"❓ No definitive verdict for {ioc}")

    if sources:
        parts.append(f"Detected by: {', '.join(sources[:5])}")
    if detections:
        parts.append(f"{len(detections)} engine detection(s)")
    if tags:
        parts.append(f"Tags: {', '.join(tags)}")

    return ". ".join(parts) + "."
