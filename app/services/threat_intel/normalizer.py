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
import datetime as _dt
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
        "per_source_enriched": {},
    }

    per_source_verdicts: list[tuple[str, str, int]] = []  # (source, verdict, score)

    for source, raw in source_results.items():
        result["raw"][source] = raw
        if raw is None:
            continue
        # Skip error/not_found responses (dict only)
        if isinstance(raw, dict) and (raw.get("error") or raw.get("not_found")):
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

    # OTX-specific structured enrichment
    if partial.get("otx"):
        result["per_source_enriched"][source] = partial["otx"]


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

    # Timeline: first submission and last analysis dates
    first_sub = attrs.get("first_submission_date")
    if first_sub:
        try:
            ts = _dt.datetime.fromtimestamp(int(first_sub), tz=_dt.timezone.utc).isoformat()
        except Exception:
            ts = str(first_sub)
        partial["timeline"].append({
            "date": ts,
            "event": f"First submitted to VirusTotal",
            "source": "VirusTotal",
        })
    last_an = attrs.get("last_analysis_date")
    if last_an:
        try:
            ts = _dt.datetime.fromtimestamp(int(last_an), tz=_dt.timezone.utc).isoformat()
        except Exception:
            ts = str(last_an)
        partial["timeline"].append({
            "date": ts,
            "event": "Last analysis on VirusTotal",
            "source": "VirusTotal",
        })

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

    # Timeline: last reported date
    last_reported = data.get("lastReportedAt", data.get("last_reported_at", ""))
    if last_reported:
        partial["timeline"].append({
            "date": last_reported,
            "event": f"Last abuse report on AbuseIPDB (score: {score}%)",
            "source": "AbuseIPDB",
        })

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

    # Structured OTX data for XDR-style per-source view
    pulses_raw = pulse_info.get("pulses") or []
    structured_pulses = []
    for p in pulses_raw:
        author = p.get("author") or {}
        author_name = author.get("username", "") if isinstance(author, dict) else str(author)
        structured_pulses.append({
            "id": p.get("id", ""),
            "name": p.get("name", ""),
            "tlp": p.get("tlp", "white"),
            "created": p.get("created", ""),
            "modified": p.get("modified", ""),
            "tags": p.get("tags") or [],
            "references": p.get("references") or [],
            "author": {"username": author_name},
            "malware_families": [
                m.get("display_name", "") for m in (p.get("malware_families") or []) if isinstance(m, dict)
            ],
            "adversary": p.get("adversary", ""),
        })

    partial["otx"] = {
        "pulse_count": pulse_info.get("count", 0),
        "pulses": structured_pulses,
        "validation": raw.get("validation") or [],
        "type_title": raw.get("type_title", ""),
        "base_indicator": raw.get("base_indicator") or {},
        "sections": raw.get("sections") or [],
    }

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

    # Timeline: last update
    last_update = raw.get("last_update") or raw.get("last_seen", "")
    if last_update:
        partial["timeline"].append({
            "date": last_update,
            "event": f"Shodan last scanned {'(' + str(len(ports)) + ' ports open)' if ports else ''}".strip(),
            "source": "Shodan",
        })

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
                if sample.get("last_seen"):
                    partial["timeline"].append({
                        "date": sample["last_seen"],
                        "event": f"Malware last seen: {sample.get('signature', '?')}",
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
                if ioc_entry.get("last_seen"):
                    partial["timeline"].append({
                        "date": ioc_entry["last_seen"],
                        "event": f"IOC last seen on ThreatFox: {ioc_entry.get('malware', '?')}",
                        "source": "ThreatFox",
                    })
                conf = ioc_entry.get("confidence_level")
                if conf is not None:
                    try:
                        if int(conf) > partial["confidence"]:
                            partial["confidence"] = int(conf)
                    except (TypeError, ValueError):
                        pass
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
            partial["detections"].append({
                "engine": "urlscan.io",
                "result": "Malicious website",
                "category": "malicious_url",
            })
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
        # Timeline: scan dates
        for scan in results[:5]:
            task = scan.get("task") or {}
            scan_time = task.get("time", "")
            scan_url = (scan.get("page") or {}).get("url", "")
            if scan_time:
                partial["timeline"].append({
                    "date": scan_time,
                    "event": f"urlscan.io scan: {scan_url[:80] if scan_url else 'URL scanned'}",
                    "source": "urlscan.io",
                })

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


def _adapt_censys(raw: dict, ioc_type: str) -> dict:
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
    # Censys v2 wraps IP data under "result"
    data = raw.get("result", raw)
    if not data or not isinstance(data, dict):
        return partial

    if data.get("ip"):
        partial["sources_hit"].append("Censys")

    loc = data.get("location") or {}
    partial["enrichment"]["geo"] = {
        "country": loc.get("country", ""),
        "country_code": loc.get("country_code", ""),
        "city": loc.get("city", ""),
        "continent": loc.get("continent", ""),
    }

    asn_info = data.get("autonomous_system") or {}
    if asn_info:
        partial["enrichment"]["geo"]["asn"] = f"AS{asn_info.get('asn', '')}".strip()
        partial["enrichment"]["geo"]["org"] = asn_info.get("description", "") or asn_info.get("name", "")

    services = data.get("services") or []
    ports: list = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        if port:
            ports.append(port)
        svc_name = svc.get("service_name", "")
        proto = svc.get("transport_protocol", "")
        if svc_name and svc_name not in ("UNKNOWN", ""):
            partial["tags"].append(f"{svc_name}/{proto}" if proto else svc_name)
        # Extract domain names from TLS certificates
        tls = svc.get("tls") or {}
        cert_data = (tls.get("certificates") or {}).get("leaf_data") or {}
        for name in (cert_data.get("names") or [])[:5]:
            if name:
                partial["artifacts"]["domains"].append(name)

    partial["enrichment"]["network"] = {"ports": ports[:30]}
    return partial


def _adapt_securitytrails(raw: dict, ioc_type: str) -> dict:
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
    dns = raw.get("current_dns") or {}
    if not dns:
        return partial

    partial["sources_hit"].append("SecurityTrails")
    dns_records: dict = {}

    # A records → IP artifacts
    a_vals = (dns.get("a") or {}).get("values") or []
    ips = [v.get("ip", "") if isinstance(v, dict) else str(v) for v in a_vals[:10]]
    ips = [ip for ip in ips if ip]
    if ips:
        partial["artifacts"]["ips"].extend(ips)
        dns_records["A"] = ips

    # MX records → domain artifacts
    mx_vals = (dns.get("mx") or {}).get("values") or []
    mxs = [v.get("hostname", "") if isinstance(v, dict) else str(v) for v in mx_vals[:5]]
    mxs = [m for m in mxs if m]
    if mxs:
        partial["artifacts"]["domains"].extend(mxs)
        dns_records["MX"] = mxs

    # NS records → domain artifacts
    ns_vals = (dns.get("ns") or {}).get("values") or []
    nss = [v.get("nameserver", "") if isinstance(v, dict) else str(v) for v in ns_vals[:5]]
    nss = [n for n in nss if n]
    if nss:
        partial["artifacts"]["domains"].extend(nss)
        dns_records["NS"] = nss

    # TXT records
    txt_vals = (dns.get("txt") or {}).get("values") or []
    txts = [v.get("value", "") if isinstance(v, dict) else str(v) for v in txt_vals[:5]]
    txts = [t for t in txts if t]
    if txts:
        dns_records["TXT"] = txts

    if dns_records:
        partial["enrichment"]["dns"] = dns_records

    return partial


def _adapt_intelx(raw: dict, ioc_type: str) -> dict:
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
    records = raw.get("records") or []
    total = raw.get("total") or len(records)

    if total > 0 or records:
        partial["sources_hit"].append("Intelligence X")
        partial["verdict"] = "suspicious"
        partial["confidence"] = min(int(total) * 10, 80)
        for rec in (records if isinstance(records, list) else [])[:10]:
            if not isinstance(rec, dict):
                continue
            if rec.get("date"):
                partial["timeline"].append({
                    "date": rec["date"],
                    "event": f"IntelX record type {rec.get('type', 'data')}",
                    "source": "Intelligence X",
                })
            if rec.get("name"):
                partial["tags"].append(str(rec["name"])[:80])

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
    "censys": _adapt_censys,
    "securitytrails": _adapt_securitytrails,
    "intelx": _adapt_intelx,
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
