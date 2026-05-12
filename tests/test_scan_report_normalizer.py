"""
Tests for the Watchlist scan-report normalizer (scan_report_normalizer.py).
Covers urlscan.io responses and generic edge-cases.
"""

import pytest
from app.services.scan_report_normalizer import normalize_scan_report, _NORMALIZERS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm(source: str, raw: dict, target: str = "example.com", target_type: str = "domain") -> dict:
    return normalize_scan_report(source, raw, target, target_type, checked_at="2024-01-01T00:00:00Z")


# ---------------------------------------------------------------------------
# urlscan — search results
# ---------------------------------------------------------------------------

class TestURLscanSearch:
    """Covers the GET /api/v1/search/ response shape."""

    def _make_result(self, malicious: bool = False, score: int = 0,
                     tags: list | None = None, categories: list | None = None):
        return {
            "page": {
                "domain": "example.com",
                "apexDomain": "example.com",
                "ip": "93.184.216.34",
                "ptr": "example.com",
                "asn": "AS15133",
                "asnname": "EDGECAST, US",
                "url": "https://www.example.com/",
                "mimeType": "text/html",
                "status": "200",
                "title": "Example Domain",
                "server": "ECS",
                "country": "US",
            },
            "screenshot": "https://urlscan.io/screenshots/uuid.png",
            "result": "https://urlscan.io/result/uuid/",
            "task": {
                "uuid": "uuid",
                "url": "https://www.example.com/",
                "reportURL": "https://urlscan.io/result/uuid/",
                "time": "2024-01-15T10:00:00.000Z",
            },
            "stats": {"malicious": 0, "suspicious": 0, "requests": 12},
            "verdicts": {
                "overall": {
                    "malicious": malicious,
                    "score": score,
                    "categories": categories or [],
                    "tags": tags or [],
                    "brands": [],
                },
                "engines": {"malicious": 1 if malicious else 0, "benign": 5},
            },
        }

    def test_clean_verdict(self):
        raw = {"total": 1, "results": [self._make_result()]}
        report = _norm("urlscan", raw)
        assert report["status"] == "success"
        assert report["verdict"] == "clean"
        assert report["verdict_score"] == 0
        assert report["main_ip"] == "93.184.216.34"
        assert report["asn"] == "AS15133"
        assert report["org"] == "EDGECAST, US"
        assert report["country"] == "US"
        assert report["final_url"] == "https://www.example.com/"
        assert report["title"] == "Example Domain"
        assert report["screenshot_url"] == "https://urlscan.io/screenshots/uuid.png"
        assert report["provider_url"] == "https://urlscan.io/result/uuid/"

    def test_malicious_verdict(self):
        raw = {"total": 1, "results": [self._make_result(malicious=True, score=90, categories=["phishing"])]}
        report = _norm("urlscan", raw, target="evil.com", target_type="url")
        assert report["verdict"] == "malicious"
        assert report["verdict_score"] == 90
        assert "phishing" in report["tags"]

    def test_suspicious_verdict_by_score(self):
        raw = {"total": 1, "results": [self._make_result(malicious=False, score=45)]}
        report = _norm("urlscan", raw)
        assert report["verdict"] == "suspicious"

    def test_no_results_returns_no_data(self):
        raw = {"total": 0, "results": []}
        report = _norm("urlscan", raw)
        assert report["status"] == "no_data"
        assert report["verdict"] is None

    def test_http_info_populated(self):
        raw = {"total": 1, "results": [self._make_result()]}
        report = _norm("urlscan", raw)
        assert report["http_info"] is not None
        assert report["http_info"]["status"] == "200"
        assert report["http_info"]["server"] == "ECS"
        assert report["http_info"]["mime_type"] == "text/html"

    def test_dns_info_populated(self):
        raw = {"total": 1, "results": [self._make_result()]}
        report = _norm("urlscan", raw)
        assert report["dns_info"] is not None
        assert report["dns_info"]["domain"] == "example.com"
        assert report["dns_info"]["apex_domain"] == "example.com"
        assert report["dns_info"]["ptr"] == "example.com"

    def test_tags_deduplication(self):
        raw = {"total": 1, "results": [
            self._make_result(tags=["malware", "phishing"], categories=["malware"])
        ]}
        report = _norm("urlscan", raw)
        assert len(report["tags"]) == len(set(report["tags"]))

    def test_total_results_preserved(self):
        raw = {"total": 42, "results": [self._make_result()]}
        report = _norm("urlscan", raw)
        assert report["total_results"] == 42

    def test_indicators_when_malicious(self):
        raw = {"total": 1, "results": [self._make_result(malicious=True, score=100)]}
        report = _norm("urlscan", raw)
        assert report["indicators"] is not None
        assert len(report["indicators"]) > 0
        # IP indicator
        ip_inds = [i for i in report["indicators"] if i["type"] == "ip"]
        assert len(ip_inds) == 1
        assert ip_inds[0]["value"] == "93.184.216.34"

    def test_no_indicators_when_clean(self):
        raw = {"total": 1, "results": [self._make_result()]}
        report = _norm("urlscan", raw)
        # No indicators for clean result with no engine detections
        assert not report["indicators"]

    def test_multi_scan_summary(self):
        results = [
            self._make_result(malicious=True, score=100),
            self._make_result(malicious=False, score=0),
            self._make_result(malicious=True, score=80),
        ]
        raw = {"total": 3, "results": results}
        report = _norm("urlscan", raw)
        assert report["scan_count"] == 3
        assert "2/3" in report.get("multi_scan_summary", "")


# ---------------------------------------------------------------------------
# urlscan — scan submission response
# ---------------------------------------------------------------------------

class TestURLscanSubmission:
    def test_submission_pending(self):
        raw = {
            "message": "Submission successful",
            "uuid": "abc123",
            "result": "https://urlscan.io/result/abc123/",
            "api": "https://urlscan.io/api/v1/result/abc123/",
            "visibility": "private",
            "url": "https://example.com",
        }
        report = _norm("urlscan", raw)
        assert report["status"] == "pending"
        assert report["provider_url"] == "https://urlscan.io/result/abc123/"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_rate_limited(self):
        raw = {"error": "Rate limit exceeded"}
        report = _norm("urlscan", raw)
        assert report["status"] == "rate_limited"

    def test_generic_error(self):
        raw = {"error": "Request timeout"}
        report = _norm("urlscan", raw)
        assert report["status"] == "failed"

    def test_not_found(self):
        raw = {"not_found": True}
        report = _norm("urlscan", raw)
        assert report["status"] == "no_data"

    def test_empty_raw(self):
        report = _norm("urlscan", {})
        assert report["status"] == "no_data"

    def test_none_raw(self):
        report = normalize_scan_report("urlscan", None, "x", "domain", "2024-01-01T00:00:00Z")
        assert report["status"] == "no_data"

    def test_unknown_provider_returns_success_base(self):
        """Unknown providers should return a base dict rather than crashing."""
        raw = {"some": "data"}
        report = _norm("unknown_provider", raw)
        assert report["status"] == "success"
        assert report["source"] == "unknown_provider"

    def test_normalizer_exception_returns_failed(self, monkeypatch):
        """Internal normalizer errors should be caught and return 'failed'."""
        from app.services import scan_report_normalizer as m

        def _bad(raw, base):
            raise RuntimeError("boom")

        monkeypatch.setitem(m._NORMALIZERS, "urlscan", _bad)
        report = _norm("urlscan", {"total": 1, "results": [{}]})
        assert report["status"] == "failed"


# ---------------------------------------------------------------------------
# Fields preserved
# ---------------------------------------------------------------------------

class TestFieldPreservation:
    def test_target_and_type_always_present(self):
        report = _norm("urlscan", {}, target="my-keyword", target_type="keyword")
        assert report["target"] == "my-keyword"
        assert report["target_type"] == "keyword"

    def test_checked_at_preserved(self):
        report = normalize_scan_report("urlscan", {}, "x", "domain", "2025-06-01T12:00:00Z")
        assert report["checked_at"] == "2025-06-01T12:00:00Z"

    def test_source_always_present(self):
        report = _norm("urlscan", {})
        assert report["source"] == "urlscan"


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------

def test_urlscan_registered():
    assert "urlscan" in _NORMALIZERS
