"""
Tests for the Threat Intelligence normalizer.
Covers per-source adapters and the overall normalize() function.
"""

import pytest
from app.services.threat_intel.normalizer import normalize, _ADAPTERS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm(source: str, raw: dict, ioc: str = "1.2.3.4", ioc_type: str = "ip") -> dict:
    """Run normalize() with a single source and return the normalized result."""
    return normalize(ioc, ioc_type, {source: raw})


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class TestVirusTotal:
    def test_v2_malicious(self):
        raw = {"positives": 15, "total": 60, "scans": {"TestEngine": {"detected": True, "result": "Trojan.X"}}}
        result = _norm("virustotal", raw)
        assert result["verdict"] == "malicious"
        assert result["confidence"] > 0
        assert any(d["engine"] == "TestEngine" for d in result["detections"])

    def test_v2_clean(self):
        raw = {"positives": 0, "total": 60}
        result = _norm("virustotal", raw)
        assert result["verdict"] == "clean"

    def test_v3_malicious(self):
        raw = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 12, "suspicious": 2, "clean": 46},
                    "last_analysis_results": {
                        "EngineA": {"category": "malicious", "result": "Malware.X"},
                        "EngineB": {"category": "suspicious", "result": "PUA"},
                    },
                    "tags": ["trojan", "stealer"],
                }
            }
        }
        result = _norm("virustotal", raw)
        assert result["verdict"] == "malicious"
        assert "trojan" in result["tags"] or "stealer" in result["tags"]
        assert len(result["detections"]) >= 2

    def test_v3_timeline_events(self):
        raw = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "clean": 59},
                    "last_analysis_date": 1700000000,
                    "first_submission_date": 1699000000,
                }
            }
        }
        result = _norm("virustotal", raw)
        dates = [e["date"] for e in result["timeline"]]
        assert any("2023" in d or "2024" in d for d in dates)


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class TestAbuseIPDB:
    def test_high_score_malicious(self):
        raw = {"data": {"ipAddress": "1.2.3.4", "abuse_confidence_score": 90, "totalReports": 50, "isp": "Bad ISP", "countryName": "Unknown"}}
        result = _norm("abuseipdb", raw)
        assert result["verdict"] == "malicious"
        assert result["enrichment"]["geo"]["isp"] == "Bad ISP"
        assert len(result["detections"]) > 0

    def test_zero_score_clean(self):
        raw = {"data": {"ipAddress": "8.8.8.8", "abuse_confidence_score": 0, "totalReports": 0}}
        result = _norm("abuseipdb", raw)
        assert result["verdict"] == "clean"

    def test_timeline_last_reported(self):
        raw = {"data": {"ipAddress": "1.2.3.4", "abuse_confidence_score": 50, "totalReports": 5, "lastReportedAt": "2024-01-01T00:00:00Z"}}
        result = _norm("abuseipdb", raw)
        assert any("AbuseIPDB" in e["source"] for e in result["timeline"])


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

class TestAlienVault:
    def test_malicious_with_pulses(self):
        raw = {
            "pulse_info": {
                "count": 15,
                "pulses": [
                    {"name": "Pulse 1", "tlp": "white", "tags": ["malware"], "created": "2024-01-01", "modified": "2024-01-02", "malware_families": [], "references": []},
                ]
            },
            "country_name": "Russia",
            "country_code": "RU",
            "asn": "AS12345",
        }
        result = _norm("alienvault", raw)
        assert result["verdict"] == "malicious"
        assert result["enrichment"]["geo"]["country"] == "Russia"
        assert "malware" in result["tags"]
        assert len(result["timeline"]) > 0

    def test_clean_no_pulses(self):
        raw = {"pulse_info": {"count": 0, "pulses": []}}
        result = _norm("alienvault", raw)
        assert result["verdict"] == "clean"

    def test_otx_structured_data(self):
        raw = {
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {
                        "id": "abc", "name": "Test Pulse", "tlp": "green",
                        "created": "2024-01-01", "modified": "2024-01-02",
                        "tags": ["ransomware"], "references": ["https://example.com"],
                        "author": {"username": "analyst1"},
                        "malware_families": [],
                    }
                ],
            },
            "validation": [{"source": "OTX", "message": "Valid", "name": "check"}],
            "type_title": "IPv4",
        }
        result = _norm("alienvault", raw)
        assert "per_source_enriched" in result
        otx = result["per_source_enriched"].get("alienvault")
        assert otx is not None
        assert otx["pulse_count"] == 2
        assert len(otx["pulses"]) == 1
        assert otx["pulses"][0]["author"]["username"] == "analyst1"
        assert len(otx["validation"]) == 1


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

class TestURLhaus:
    def test_malware_verdict(self):
        raw = {
            "query_status": "is_malware",
            "threat": "malware_download",
            "tags": ["elf", "mozi"],
            "urls": [
                {"url": "http://bad.com/file.elf", "url_status": "online", "tags": ["mozi"], "date_added": "2024-01-01"},
            ],
        }
        result = _norm("urlhaus", raw)
        assert result["verdict"] == "malicious"
        assert "http://bad.com/file.elf" in result["artifacts"]["urls"]
        assert len(result["timeline"]) > 0

    def test_no_results_clean(self):
        raw = {"query_status": "no_results"}
        result = _norm("urlhaus", raw)
        assert result["verdict"] == "clean"


# ---------------------------------------------------------------------------
# PhishTank
# ---------------------------------------------------------------------------

class TestPhishTank:
    def test_phishing_confirmed(self):
        raw = {"results": {"in_database": True, "valid": True, "phish_submit_time": "2024-01-01T00:00:00Z"}}
        result = _norm("phishtank", raw)
        assert result["verdict"] == "malicious"
        assert "phishing" in result["tags"]
        assert len(result["timeline"]) > 0

    def test_not_in_database(self):
        raw = {"results": {"in_database": False}}
        result = _norm("phishtank", raw)
        assert result["verdict"] == "clean"


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

class TestShodan:
    def test_with_vulns(self):
        raw = {
            "ip_str": "1.2.3.4",
            "ports": [22, 80, 443],
            "org": "Example Corp",
            "country_name": "Germany",
            "os": "Linux",
            "vulns": {"CVE-2021-44228": {"cvss": 10.0}},
            "hostnames": ["example.com"],
            "last_update": "2024-01-15T00:00:00",
        }
        result = _norm("shodan", raw)
        assert result["verdict"] == "suspicious"
        assert "CVE-2021-44228" in result["tags"]
        assert 22 in result["enrichment"]["network"]["ports"]
        assert "example.com" in result["artifacts"]["domains"]
        assert len(result["timeline"]) > 0

    def test_no_vulns(self):
        raw = {"ip_str": "8.8.8.8", "ports": [53], "org": "Google"}
        result = _norm("shodan", raw)
        assert result["verdict"] == "unknown"


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------

class TestMalwareBazaar:
    def test_hash_found(self):
        raw = {
            "query_status": "ok",
            "data": [
                {
                    "sha256_hash": "abc123",
                    "file_name": "malware.exe",
                    "file_type": "exe",
                    "signature": "AgentTesla",
                    "tags": ["trojan", "stealer"],
                    "first_seen": "2024-01-01 00:00:00",
                    "last_seen": "2024-01-15 00:00:00",
                }
            ],
        }
        result = _norm("malwarebazaar", raw, ioc_type="hash")
        assert result["verdict"] == "malicious"
        assert "AgentTesla" in result["tags"] or "trojan" in result["tags"]
        # Should have both first_seen and last_seen timeline events
        assert len(result["timeline"]) >= 2

    def test_hash_not_found(self):
        raw = {"query_status": "hash_not_found"}
        result = _norm("malwarebazaar", raw, ioc_type="hash")
        assert result["verdict"] == "clean"


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------

class TestThreatFox:
    def test_ioc_found(self):
        raw = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "1.2.3.4:4444",
                    "ioc_type": "ip:port",
                    "malware": "Cobalt Strike",
                    "confidence_level": 75,
                    "tags": ["cobalt_strike"],
                    "first_seen": "2024-01-01 00:00:00",
                    "last_seen": "2024-02-01 00:00:00",
                }
            ],
        }
        result = _norm("threatfox", raw)
        assert result["verdict"] == "malicious"
        # Adapter sets base confidence=90; per-IOC confidence_level only raises if higher
        assert result["confidence"] >= 75
        assert "Cobalt Strike" in result["tags"]
        # Should have both first_seen and last_seen timeline events
        assert len(result["timeline"]) >= 2

    def test_no_result(self):
        raw = {"query_status": "no_result"}
        result = _norm("threatfox", raw)
        assert result["verdict"] == "clean"


# ---------------------------------------------------------------------------
# URLscan
# ---------------------------------------------------------------------------

class TestURLscan:
    def test_malicious_scan(self):
        raw = {
            "total": 1,
            "results": [
                {
                    "page": {"domain": "evil.com", "country": "RU", "asn": "AS666", "asnname": "Bad ASN"},
                    "verdicts": {"overall": {"malicious": True, "score": 100, "categories": ["phishing"]}},
                    "result": "https://urlscan.io/result/abc123/",
                    "task": {"time": "2024-01-01T12:00:00Z"},
                }
            ],
        }
        result = _norm("urlscan", raw, ioc_type="url")
        assert result["verdict"] == "malicious"
        assert "phishing" in result["tags"]
        assert len(result["timeline"]) > 0
        assert any(d["engine"] == "urlscan.io" for d in result["detections"])

    def test_no_results(self):
        raw = {"total": 0, "results": []}
        result = _norm("urlscan", raw, ioc_type="url")
        assert result["verdict"] == "unknown"


# ---------------------------------------------------------------------------
# HIBP
# ---------------------------------------------------------------------------

class TestHIBP:
    def test_breaches_found(self):
        raw = [
            {"Name": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 152000000, "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "LinkedIn", "BreachDate": "2012-05-05", "PwnCount": 164600000, "DataClasses": ["Email addresses"]},
        ]
        result = _norm("hibp", raw, ioc_type="email")
        assert result["verdict"] == "suspicious"
        assert any(d["engine"] == "HIBP" for d in result["detections"])
        assert len(result["timeline"]) >= 2

    def test_no_breaches(self):
        raw = []
        result = _norm("hibp", raw, ioc_type="email")
        assert result["verdict"] == "clean"


# ---------------------------------------------------------------------------
# Censys (new adapter)
# ---------------------------------------------------------------------------

class TestCensys:
    def test_ip_result(self):
        raw = {
            "result": {
                "ip": "1.2.3.4",
                "location": {"country": "Germany", "country_code": "DE", "city": "Berlin", "continent": "Europe"},
                "autonomous_system": {"asn": 1234, "name": "Example ISP", "description": "Example ISP"},
                "services": [
                    {"port": 22, "transport_protocol": "TCP", "service_name": "SSH"},
                    {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"},
                ],
            }
        }
        result = _norm("censys", raw)
        assert "Censys" in result["sources_hit"]
        assert result["enrichment"]["geo"]["country"] == "Germany"
        assert result["enrichment"]["geo"]["country_code"] == "DE"
        assert 22 in result["enrichment"]["network"]["ports"]
        assert 443 in result["enrichment"]["network"]["ports"]

    def test_missing_result_wrapper(self):
        """Should handle direct data without 'result' wrapper gracefully."""
        raw = {
            "ip": "1.2.3.4",
            "location": {"country": "US"},
            "autonomous_system": {"asn": 15169},
            "services": [{"port": 80, "transport_protocol": "TCP", "service_name": "HTTP"}],
        }
        result = _norm("censys", raw)
        # Should work with direct data too
        assert result["enrichment"]["network"]["ports"] is not None

    def test_no_data(self):
        raw = {"not_found": True}
        result = _norm("censys", raw)
        assert result["verdict"] == "unknown"


# ---------------------------------------------------------------------------
# SecurityTrails (new adapter)
# ---------------------------------------------------------------------------

class TestSecurityTrails:
    def test_dns_data(self):
        raw = {
            "current_dns": {
                "a": {"values": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]},
                "mx": {"values": [{"hostname": "mail.example.com"}]},
                "ns": {"values": [{"nameserver": "ns1.example.com"}]},
                "txt": {"values": [{"value": "v=spf1 include:example.com ~all"}]},
            }
        }
        result = _norm("securitytrails", raw, ioc_type="domain")
        assert "SecurityTrails" in result["sources_hit"]
        assert "1.2.3.4" in result["artifacts"]["ips"]
        assert "5.6.7.8" in result["artifacts"]["ips"]
        assert "mail.example.com" in result["artifacts"]["domains"]
        assert "ns1.example.com" in result["artifacts"]["domains"]
        assert "A" in result["enrichment"]["dns"]
        assert "MX" in result["enrichment"]["dns"]
        assert "TXT" in result["enrichment"]["dns"]

    def test_no_dns(self):
        raw = {}
        result = _norm("securitytrails", raw, ioc_type="domain")
        assert result["verdict"] == "unknown"
        assert result["sources_hit"] == []


# ---------------------------------------------------------------------------
# IntelX (new adapter)
# ---------------------------------------------------------------------------

class TestIntelX:
    def test_records_found(self):
        raw = {
            "total": 5,
            "records": [
                {"type": 1, "name": "leaked@example.com", "date": "2024-01-01T00:00:00Z", "bucket": "pastes", "size": 2048},
                {"type": 2, "name": "other record", "date": "2023-06-15T00:00:00Z", "bucket": "darkweb", "size": 512},
            ],
        }
        result = _norm("intelx", raw, ioc_type="email")
        assert "Intelligence X" in result["sources_hit"]
        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 50  # min(5*10, 80)
        assert len(result["timeline"]) == 2

    def test_no_records(self):
        raw = {"total": 0, "records": []}
        result = _norm("intelx", raw, ioc_type="email")
        assert result["verdict"] == "unknown"
        assert result["sources_hit"] == []


# ---------------------------------------------------------------------------
# Adapter registry completeness
# ---------------------------------------------------------------------------

def test_all_expected_adapters_registered():
    """Ensure all TI service types have a registered adapter."""
    expected = {
        "virustotal", "abuseipdb", "alienvault", "urlhaus", "phishtank",
        "shodan", "malwarebazaar", "threatfox", "urlscan", "hibp",
        "censys", "securitytrails", "intelx",
    }
    missing = expected - set(_ADAPTERS.keys())
    assert not missing, f"Missing adapters for: {missing}"


# ---------------------------------------------------------------------------
# Aggregate verdict / confidence
# ---------------------------------------------------------------------------

def test_aggregate_verdict_multiple_sources():
    """Most severe verdict across sources should win."""
    raw_results = {
        "virustotal": {"positives": 20, "total": 60},
        "urlhaus": {"query_status": "no_results"},
    }
    result = normalize("bad.com", "domain", raw_results)
    assert result["verdict"] == "malicious"


def test_normalize_handles_error_sources():
    """Sources with errors should be skipped gracefully."""
    raw_results = {
        "virustotal": {"error": "API key not configured"},
        "urlhaus": {"not_found": True},
        "malwarebazaar": {"query_status": "hash_not_found"},
    }
    result = normalize("abc123", "hash", raw_results)
    assert result["verdict"] in ("clean", "unknown")
    assert isinstance(result["detections"], list)
    assert isinstance(result["artifacts"], dict)


def test_normalize_deduplicates_tags():
    raw_results = {
        "urlhaus": {
            "query_status": "is_malware",
            "threat": "malware_download",
            "tags": ["elf", "mozi"],
            "urls": [{"url": "http://bad.com/1", "tags": ["elf"]}, {"url": "http://bad.com/2", "tags": ["mozi"]}],
        }
    }
    result = normalize("1.2.3.4", "ip", raw_results)
    # Tags should be deduplicated
    assert len(result["tags"]) == len(set(result["tags"]))


def test_summary_string_populated():
    raw_results = {
        "virustotal": {"positives": 5, "total": 60},
    }
    result = normalize("malware.exe", "hash", raw_results)
    assert result["summary"]
    assert "malware.exe" in result["summary"] or "malicious" in result["summary"].lower() or "suspicious" in result["summary"].lower()
