"""
Phase 1 unit tests for the Impersonation Monitoring scanner — TS-IMP-001.
Covers M3 (DMARC/SPF) and M8 (NRD fuzzy match) plus the scheduler dueness
helper.
"""
import asyncio
import sys
import types
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from app.services.impersonation import scanner as imp_scanner
from app.services.scheduler import _is_imp_rule_due


# ── M3: Email/DMARC ──────────────────────────────────────────────────────────

def _install_fake_checkdmarc(domain_results):
    """Insert a fake ``checkdmarc`` module into sys.modules for the test."""
    fake = types.ModuleType("checkdmarc")

    def check_domains(domains, skip_tls=True):  # noqa: ARG001
        return [domain_results[d] for d in domains if d in domain_results]

    fake.check_domains = check_domains
    sys.modules["checkdmarc"] = fake


def test_m3_email_scan_returns_empty_when_no_official_domains():
    rule = {"brand_name": "Acme", "official_domains": []}
    findings = asyncio.run(imp_scanner._scan_m3_email(rule))
    assert findings == []


def test_m3_email_scan_emits_missing_dmarc_finding():
    _install_fake_checkdmarc(
        {
            "acme.com": {
                "dmarc": {"record": ""},
                "spf": {"record": "v=spf1 -all"},
            }
        }
    )
    rule = {"brand_name": "Acme", "official_domains": ["acme.com"]}
    findings = asyncio.run(imp_scanner._scan_m3_email(rule))
    assert len(findings) == 1
    assert findings[0]["module"] == "m3"
    assert findings[0]["finding_type"] == "missing_dmarc"
    assert findings[0]["target_identifier"] == "acme.com"
    assert findings[0]["threat_score"] == 70


def test_m3_email_scan_emits_weak_dmarc_when_policy_is_none():
    _install_fake_checkdmarc(
        {
            "acme.com": {
                "dmarc": {
                    "record": "v=DMARC1; p=none",
                    "tags": {"p": {"value": "none"}},
                },
                "spf": {"record": "v=spf1 -all"},
            }
        }
    )
    rule = {"brand_name": "Acme", "official_domains": ["acme.com"]}
    findings = asyncio.run(imp_scanner._scan_m3_email(rule))
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "weak_dmarc"
    assert findings[0]["threat_score"] == 40


def test_m3_email_scan_emits_missing_spf_in_addition_to_strong_dmarc():
    _install_fake_checkdmarc(
        {
            "acme.com": {
                "dmarc": {
                    "record": "v=DMARC1; p=reject",
                    "tags": {"p": {"value": "reject"}},
                },
                "spf": {"record": ""},
            }
        }
    )
    rule = {"brand_name": "Acme", "official_domains": ["acme.com"]}
    findings = asyncio.run(imp_scanner._scan_m3_email(rule))
    assert [f["finding_type"] for f in findings] == ["missing_spf"]


def test_m3_email_scan_skips_when_checkdmarc_missing(monkeypatch):
    # Ensure import fails inside the function.
    monkeypatch.setitem(sys.modules, "checkdmarc", None)
    rule = {"brand_name": "Acme", "official_domains": ["acme.com"]}
    findings = asyncio.run(imp_scanner._scan_m3_email(rule))
    assert findings == []


# ── M8: NRD domain similarity ────────────────────────────────────────────────

def test_m8_domains_returns_empty_without_brand_name():
    rule = {"brand_name": "", "official_domains": [], "min_impersonation_score": 40}
    findings = asyncio.run(imp_scanner._scan_m8_domains(rule))
    assert findings == []


def test_m8_domains_emits_finding_for_similar_nrd_domain():
    rule = {
        "brand_name": "Acme",
        "official_domains": ["acme.com"],
        "min_impersonation_score": 40,
    }
    feed = ["acme-login.com", "totally-unrelated.example", "acme.com"]
    with patch(
        "app.services.lookalike.nrd_feed.fetch_nrd_domains",
        new_callable=AsyncMock,
    ) as mocked:
        mocked.return_value = feed
        findings = asyncio.run(imp_scanner._scan_m8_domains(rule))

    identifiers = [f["target_identifier"] for f in findings]
    assert "acme-login.com" in identifiers
    # Official domain must be filtered out.
    assert "acme.com" not in identifiers
    # Unrelated domain should not be a finding.
    assert "totally-unrelated.example" not in identifiers
    for finding in findings:
        assert finding["module"] == "m8"
        assert finding["platform"] == "nrd"
        assert 0 < finding["threat_score"] <= 95


def test_m8_domains_respects_min_score_threshold():
    rule = {
        "brand_name": "Zircon",
        "official_domains": [],
        "min_impersonation_score": 90,
    }
    feed = ["random-news.example", "totally-unrelated.test"]
    with patch(
        "app.services.lookalike.nrd_feed.fetch_nrd_domains",
        new_callable=AsyncMock,
    ) as mocked:
        mocked.return_value = feed
        findings = asyncio.run(imp_scanner._scan_m8_domains(rule))
    assert findings == []


# ── Scheduler dueness helper ─────────────────────────────────────────────────

class _FakeRule:
    def __init__(self, schedule_cron, last_scan_at):
        self.schedule_cron = schedule_cron
        self.last_scan_at = last_scan_at


def test_is_imp_rule_due_returns_true_when_never_scanned():
    rule = _FakeRule("0 */6 * * *", None)
    assert _is_imp_rule_due(rule) is True


def test_is_imp_rule_due_returns_false_when_recently_scanned():
    rule = _FakeRule("0 */6 * * *", datetime.utcnow() - timedelta(minutes=30))
    assert _is_imp_rule_due(rule) is False


def test_is_imp_rule_due_returns_true_after_hour_interval_elapses():
    rule = _FakeRule("0 */6 * * *", datetime.utcnow() - timedelta(hours=7))
    assert _is_imp_rule_due(rule) is True


def test_is_imp_rule_due_supports_minute_step_cron():
    rule = _FakeRule("*/15 * * * *", datetime.utcnow() - timedelta(minutes=20))
    assert _is_imp_rule_due(rule) is True


def test_is_imp_rule_due_supports_named_aliases():
    rule = _FakeRule("@hourly", datetime.utcnow() - timedelta(minutes=70))
    assert _is_imp_rule_due(rule) is True
    rule_recent = _FakeRule("@daily", datetime.utcnow() - timedelta(hours=1))
    assert _is_imp_rule_due(rule_recent) is False
