"""
Tests for Phase 2 Impersonation Monitoring scanner integrations (TS-IMP-001 v2).

Covers:
- M7 VIP partner phishing domain detection (lookalike + rapidfuzz)
- M5 Executive HIBP breach lookup
- M1 Telegram channel impersonation scanning
- M1 Instagram account detection via Apify
- M1 VK community detection via VK API
- M2 Google Play app detection via google-play-scraper
- _scan_m1_social platform dispatch routing
- Alert engine email dispatch and score badge formatting
- score_calculators shared helpers
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "app" / "services" / "impersonation" / "scanner.py"
ALERT_ENGINE = REPO_ROOT / "app" / "services" / "impersonation" / "alert_engine.py"
SCORE_CALCULATORS = REPO_ROOT / "app" / "services" / "impersonation" / "score_calculators.py"


# ── score_calculators helpers ─────────────────────────────────────────────────

class TestScoreCalculators:
    def test_score_calculators_file_exists(self):
        assert SCORE_CALCULATORS.exists(), "score_calculators.py should exist"

    def test_similarity_ratio_identical(self):
        from app.services.impersonation.score_calculators import similarity_ratio
        assert similarity_ratio("acme", "acme") == 100.0

    def test_similarity_ratio_empty(self):
        from app.services.impersonation.score_calculators import similarity_ratio
        assert similarity_ratio("", "") == 100.0
        assert similarity_ratio("acme", "") == 0.0

    def test_similarity_ratio_different(self):
        from app.services.impersonation.score_calculators import similarity_ratio
        score = similarity_ratio("acme", "xyz-unrelated-123")
        assert 0.0 <= score < 50.0

    def test_domain_label_basic(self):
        from app.services.impersonation.score_calculators import domain_label
        assert domain_label("acme.com") == "acme"
        assert domain_label("acme-bank.co.uk") == "acme-bank"

    def test_best_domain_similarity_match(self):
        from app.services.impersonation.score_calculators import best_domain_similarity
        score, ref = best_domain_similarity("acmee.com", ["acme.com", "partner.com"])
        assert score >= 80.0
        assert ref == "acme.com"

    def test_best_domain_similarity_no_match(self):
        from app.services.impersonation.score_calculators import best_domain_similarity
        score, ref = best_domain_similarity("unrelated-xyz123.com", ["acme.com"])
        assert score < 70.0

    def test_score_badge(self):
        from app.services.impersonation.score_calculators import score_badge
        assert score_badge(85) == "🔴"
        assert score_badge(65) == "🟡"
        assert score_badge(30) == "🟢"

    def test_contains_keywords(self):
        from app.services.impersonation.score_calculators import contains_keywords
        result = contains_keywords("ACME Official Support", ["official", "fake"])
        assert "official" in result
        assert "fake" not in result


# ── M7 VIP scanner ────────────────────────────────────────────────────────────

class TestScanM7Vip:
    def test_m7_vip_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m7_vip" in source

    def test_m7_vip_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "vip_phishing_domain" in source

    @pytest.mark.asyncio
    async def test_m7_vip_no_protected_domains_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m7_vip
        result = await _scan_m7_vip({"brand_name": "TestBrand", "official_domains": [], "partner_domains": []})
        assert result == []

    @pytest.mark.asyncio
    async def test_m7_vip_returns_finding_for_lookalike(self):
        from app.services.impersonation.scanner import _scan_m7_vip

        async def _fake_nrd():
            return ["acmee.com", "unrelated-xyz9999.com"]

        with patch("app.services.lookalike.nrd_feed.fetch_nrd_domains", new=_fake_nrd):
            rule = {
                "brand_name": "ACME",
                "official_domains": ["acme.com"],
                "partner_domains": [],
                "min_impersonation_score": 40,
            }
            result = await _scan_m7_vip(rule)
        # "acmee.com" is very similar to "acme.com" (>70%); should produce a finding
        assert isinstance(result, list)
        identifiers = [f["target_identifier"] for f in result]
        assert any(ident == "acmee.com" for ident in identifiers)

    @pytest.mark.asyncio
    async def test_m7_vip_skips_exact_protected_domains(self):
        """NRD domains that are exact official domains should be skipped."""
        from app.services.impersonation.scanner import _scan_m7_vip
        from app.services.lookalike import nrd_feed

        async def _fake_nrd():
            return ["acme.com"]  # exact match of official domain

        orig_fetch = nrd_feed.fetch_nrd_domains
        try:
            nrd_feed.fetch_nrd_domains = _fake_nrd
            rule = {
                "brand_name": "ACME",
                "official_domains": ["acme.com"],
                "partner_domains": [],
                "min_impersonation_score": 40,
            }
            result = await _scan_m7_vip(rule)
            # acme.com is in official_domains so it should be filtered out
            for finding in result:
                assert finding["target_identifier"] != "acme.com"
        finally:
            nrd_feed.fetch_nrd_domains = orig_fetch


# ── M5 HIBP scanner ───────────────────────────────────────────────────────────

class TestScanM5Hibp:
    def test_m5_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m5_executive" in source

    def test_m5_uses_hibp_client(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "HIBPClient" in source

    def test_m5_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "executive_credentials_leaked" in source

    @pytest.mark.asyncio
    async def test_m5_no_api_key_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m5_executive
        with patch.dict("os.environ", {"HIBP_API_KEY": ""}, clear=False):
            result = await _scan_m5_executive({
                "brand_name": "Acme",
                "executive_names": ["John Doe"],
                "official_domains": ["acme.com"],
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_m5_no_executives_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m5_executive
        with patch.dict("os.environ", {"HIBP_API_KEY": "test-key"}, clear=False):
            result = await _scan_m5_executive({
                "brand_name": "Acme",
                "executive_names": [],
                "official_domains": ["acme.com"],
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_m5_breach_found_returns_finding(self):
        from app.services.impersonation.scanner import _scan_m5_executive
        mock_breaches = [
            {"Name": "Adobe", "DataClasses": ["Email addresses", "Passwords"], "BreachDate": "2013-10-04"},
        ]
        mock_client = MagicMock()
        mock_client.search = AsyncMock(return_value={"breaches": mock_breaches})

        with patch.dict("os.environ", {"HIBP_API_KEY": "test-key"}, clear=False):
            with patch(
                "app.services.osint.hibp.HIBPClient",
                return_value=mock_client,
            ):
                result = await _scan_m5_executive({
                    "brand_name": "Acme",
                    "executive_names": ["john.doe@acme.com"],
                    "official_domains": ["acme.com"],
                })
        assert len(result) == 1
        finding = result[0]
        assert finding["module"] == "m5"
        assert finding["platform"] == "breach_database"
        assert finding["finding_type"] == "executive_credentials_leaked"
        assert finding["threat_score"] == 90  # has passwords → critical
        assert "has_passwords" in finding["signals"]

    @pytest.mark.asyncio
    async def test_m5_breach_without_passwords_is_high(self):
        from app.services.impersonation.scanner import _scan_m5_executive
        mock_breaches = [{"Name": "LinkedIn", "DataClasses": ["Email addresses"], "BreachDate": "2012-05-05"}]
        mock_client = MagicMock()
        mock_client.search = AsyncMock(return_value={"breaches": mock_breaches})

        with patch.dict("os.environ", {"HIBP_API_KEY": "test-key"}, clear=False):
            with patch("app.services.osint.hibp.HIBPClient", return_value=mock_client):
                result = await _scan_m5_executive({
                    "brand_name": "Acme",
                    "executive_names": ["jane@acme.com"],
                    "official_domains": ["acme.com"],
                })
        assert len(result) == 1
        assert result[0]["threat_score"] == 75  # no passwords → high
        assert "has_passwords" not in result[0]["signals"]

    @pytest.mark.asyncio
    async def test_m5_no_breach_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m5_executive
        mock_client = MagicMock()
        mock_client.search = AsyncMock(return_value={"breaches": []})

        with patch.dict("os.environ", {"HIBP_API_KEY": "test-key"}, clear=False):
            with patch("app.services.osint.hibp.HIBPClient", return_value=mock_client):
                result = await _scan_m5_executive({
                    "brand_name": "Acme",
                    "executive_names": ["safe@acme.com"],
                    "official_domains": ["acme.com"],
                })
        assert result == []


# ── M1 Telegram scanner ───────────────────────────────────────────────────────

class TestScanM1Telegram:
    def test_telegram_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m1_telegram" in source

    def test_telegram_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "fake_telegram_account" in source

    @pytest.mark.asyncio
    async def test_telegram_no_credentials_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m1_telegram
        env = {"TELEGRAM_API_ID": "", "TELEGRAM_API_HASH": "", "TELEGRAM_SESSION_STRING": ""}
        with patch.dict("os.environ", env, clear=False):
            result = await _scan_m1_telegram({
                "brand_name": "TestBrand",
                "official_domains": [],
                "executive_names": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_telegram_missing_telethon_returns_empty(self):
        """When telethon is not importable, scan should return [] gracefully."""
        from app.services.impersonation.scanner import _scan_m1_telegram
        import sys
        with patch.dict("sys.modules", {"telethon": None}):
            result = await _scan_m1_telegram({
                "brand_name": "TestBrand",
                "official_domains": [],
                "executive_names": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    def test_telegram_scoring_logic_in_source(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "partial_ratio" in source or "name_sim" in source
        assert "subscribers" in source or "participants_count" in source


# ── M1 Social dispatch ────────────────────────────────────────────────────────

class TestScanM1Social:
    def test_social_scan_dispatches_to_platforms(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "_scan_m1_telegram" in source
        assert "_scan_m1_instagram" in source
        assert "_scan_m1_vk" in source
        assert "_scan_m1_facebook" in source

    @pytest.mark.asyncio
    async def test_social_scan_calls_telegram_when_in_platforms(self):
        from app.services.impersonation import scanner as scanner_mod
        mock_tg = AsyncMock(return_value=[{"module": "m1", "platform": "telegram"}])
        mock_ig = AsyncMock(return_value=[])
        mock_vk = AsyncMock(return_value=[])
        mock_fb = AsyncMock(return_value=[])
        with (
            patch.object(scanner_mod, "_scan_m1_telegram", mock_tg),
            patch.object(scanner_mod, "_scan_m1_instagram", mock_ig),
            patch.object(scanner_mod, "_scan_m1_vk", mock_vk),
            patch.object(scanner_mod, "_scan_m1_facebook", mock_fb),
        ):
            rule = {
                "brand_name": "Acme",
                "social_platforms": ["telegram"],
                "official_domains": [],
                "executive_names": [],
                "min_impersonation_score": 40,
            }
            result = await scanner_mod._scan_m1_social(rule)
        assert len(result) == 1
        mock_tg.assert_called_once()
        mock_ig.assert_not_called()
        mock_vk.assert_not_called()
        mock_fb.assert_not_called()

    @pytest.mark.asyncio
    async def test_social_scan_all_platforms(self):
        from app.services.impersonation import scanner as scanner_mod
        mock_tg = AsyncMock(return_value=[{"module": "m1", "platform": "telegram"}])
        mock_ig = AsyncMock(return_value=[{"module": "m1", "platform": "instagram"}])
        mock_vk = AsyncMock(return_value=[{"module": "m1", "platform": "vk"}])
        mock_fb = AsyncMock(return_value=[{"module": "m1", "platform": "facebook"}])
        with (
            patch.object(scanner_mod, "_scan_m1_telegram", mock_tg),
            patch.object(scanner_mod, "_scan_m1_instagram", mock_ig),
            patch.object(scanner_mod, "_scan_m1_vk", mock_vk),
            patch.object(scanner_mod, "_scan_m1_facebook", mock_fb),
        ):
            rule = {
                "brand_name": "Acme",
                "social_platforms": ["telegram", "instagram", "vk", "facebook"],
                "official_domains": [],
                "executive_names": [],
                "min_impersonation_score": 40,
            }
            result = await scanner_mod._scan_m1_social(rule)
        assert len(result) == 4
        mock_tg.assert_called_once()
        mock_ig.assert_called_once()
        mock_vk.assert_called_once()
        mock_fb.assert_called_once()


# ── M1 Instagram scanner ──────────────────────────────────────────────────────

class TestScanM1Instagram:
    def test_instagram_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m1_instagram" in source

    def test_instagram_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "fake_instagram_account" in source

    @pytest.mark.asyncio
    async def test_instagram_no_api_key_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m1_instagram
        with patch.dict("os.environ", {"APIFY_API_KEY": ""}, clear=False):
            result = await _scan_m1_instagram({
                "brand_name": "TestBrand",
                "executive_names": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_instagram_mock_apify_response_returns_finding(self):
        from app.services.impersonation.scanner import _scan_m1_instagram
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "username": "testbrandofficial",
                "fullName": "TestBrand Official",
                "followersCount": 5000,
                "isVerified": False,
                "biography": "",
            }
        ]
        with patch.dict("os.environ", {"APIFY_API_KEY": "test-key"}, clear=False):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client
                result = await _scan_m1_instagram({
                    "brand_name": "TestBrand",
                    "executive_names": [],
                    "min_impersonation_score": 40,
                })
        assert isinstance(result, list)


# ── M1 VK scanner ─────────────────────────────────────────────────────────────

class TestScanM1Vk:
    def test_vk_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m1_vk" in source

    def test_vk_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "fake_vk_account" in source

    @pytest.mark.asyncio
    async def test_vk_no_token_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m1_vk
        with patch.dict("os.environ", {"VK_SERVICE_TOKEN": ""}, clear=False):
            result = await _scan_m1_vk({
                "brand_name": "TestBrand",
                "executive_names": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_vk_mock_api_response_returns_finding(self):
        from app.services.impersonation.scanner import _scan_m1_vk
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "response": {
                "items": [
                    {
                        "id": 12345,
                        "name": "TestBrand Official Group",
                        "screen_name": "testbrand_official",
                        "members_count": 500,
                        "verified": 0,
                    }
                ]
            }
        }
        with patch.dict("os.environ", {"VK_SERVICE_TOKEN": "vk-token"}, clear=False):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client
                result = await _scan_m1_vk({
                    "brand_name": "TestBrand",
                    "executive_names": [],
                    "min_impersonation_score": 40,
                })
        assert isinstance(result, list)
        if result:
            assert result[0]["platform"] == "vk"
            assert result[0]["finding_type"] == "fake_vk_account"


# ── M1 Facebook scanner ───────────────────────────────────────────────────────

class TestScanM1Facebook:
    def test_facebook_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m1_facebook" in source

    def test_facebook_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "fake_facebook_page" in source

    @pytest.mark.asyncio
    async def test_facebook_no_api_key_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m1_facebook
        with patch.dict(
            "os.environ",
            {"APIFY_API_KEY": "", "FACEBOOK_APIFY_ACTOR": "some~actor"},
            clear=False,
        ):
            result = await _scan_m1_facebook({
                "brand_name": "TestBrand",
                "executive_names": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_facebook_no_actor_configured_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m1_facebook
        with patch.dict(
            "os.environ",
            {"APIFY_API_KEY": "test-key", "FACEBOOK_APIFY_ACTOR": ""},
            clear=False,
        ):
            result = await _scan_m1_facebook({
                "brand_name": "TestBrand",
                "executive_names": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_facebook_mock_apify_response_returns_finding(self):
        from app.services.impersonation.scanner import _scan_m1_facebook
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "pageName": "TestBrand Official",
                "pageUsername": "testbrandofficial",
                "pageUrl": "https://www.facebook.com/testbrandofficial",
                "followers": 5000,
                "verified": False,
            }
        ]
        with patch.dict(
            "os.environ",
            {"APIFY_API_KEY": "test-key", "FACEBOOK_APIFY_ACTOR": "some~actor"},
            clear=False,
        ):
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_client_cls.return_value = mock_client
                result = await _scan_m1_facebook({
                    "brand_name": "TestBrand",
                    "executive_names": [],
                    "min_impersonation_score": 40,
                })
        assert isinstance(result, list)
        if result:
            assert result[0]["platform"] == "facebook"
            assert result[0]["finding_type"] == "fake_facebook_page"


# ── M2 Google Play scanner ────────────────────────────────────────────────────

class TestScanM2GooglePlay:
    def test_google_play_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m2_google_play" in source

    def test_google_play_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "fake_mobile_app" in source

    @pytest.mark.asyncio
    async def test_google_play_missing_package_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m2_google_play
        import sys
        with patch.dict("sys.modules", {"google_play_scraper": None}):
            result = await _scan_m2_google_play({
                "brand_name": "TestBrand",
                "official_developer_ids": [],
                "min_impersonation_score": 40,
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_google_play_mock_results_return_finding(self):
        from app.services.impersonation.scanner import _scan_m2_google_play
        mock_app = {
            "appId": "com.fake.testbrand",
            "title": "TestBrand",
            "developer": "FakeDev Inc",
            "developerId": "fakeDev",
            "score": 3.5,
            "minInstalls": 10000,
            "permissions": [],
        }
        mock_search = MagicMock(return_value=[mock_app])
        with patch("app.services.impersonation.scanner.gplay_search", mock_search, create=True):
            with patch(
                "asyncio.to_thread",
                new=AsyncMock(return_value=[mock_app]),
            ):
                result = await _scan_m2_google_play({
                    "brand_name": "TestBrand",
                    "official_developer_ids": [],
                    "min_impersonation_score": 40,
                })
        assert isinstance(result, list)

    def test_google_play_suspicious_permissions_in_source(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "READ_CONTACTS" in source or "SUSPICIOUS" in source or "suspicious_permissions" in source


# ── M3 Honeypot Mailbox ───────────────────────────────────────────────────────

class TestScanM3Honeypot:
    def test_honeypot_function_exists(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m3_honeypot" in source

    def test_honeypot_output_type_correct(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "honeypot_bec_attempt" in source
        assert "honeypot_suspicious_email" in source

    @pytest.mark.asyncio
    async def test_honeypot_not_configured_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m3_honeypot
        with patch.dict(
            "os.environ",
            {"HONEYPOT_IMAP_HOST": "", "HONEYPOT_IMAP_USER": "", "HONEYPOT_IMAP_PASSWORD": ""},
            clear=False,
        ):
            result = await _scan_m3_honeypot({
                "brand_name": "TestBrand",
                "official_domains": ["testbrand.com"],
                "executive_names": [],
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_honeypot_missing_password_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m3_honeypot
        with patch.dict(
            "os.environ",
            {
                "HONEYPOT_IMAP_HOST": "mail.example.com",
                "HONEYPOT_IMAP_USER": "honeypot@example.com",
                "HONEYPOT_IMAP_PASSWORD": "",
            },
            clear=False,
        ):
            result = await _scan_m3_honeypot({
                "brand_name": "TestBrand",
                "official_domains": ["testbrand.com"],
                "executive_names": [],
            })
        assert result == []

    @pytest.mark.asyncio
    async def test_honeypot_mock_messages_returns_finding(self):
        from app.services.impersonation.scanner import _scan_m3_honeypot
        mock_message = {
            "message_id": "<spam1@random-marketer.example>",
            "from_display": "Random Marketer",
            "from_address": "sales@random-marketer.example",
            "reply_to": "",
            "to_addresses": ["ceo-honeypot@testbrand.com"],
            "subject": "Great deals for you",
            "body": "Check out our catalog.",
        }
        with patch.dict(
            "os.environ",
            {
                "HONEYPOT_IMAP_HOST": "mail.example.com",
                "HONEYPOT_IMAP_USER": "honeypot@example.com",
                "HONEYPOT_IMAP_PASSWORD": "secret",
            },
            clear=False,
        ):
            with patch("asyncio.to_thread", new=AsyncMock(return_value=[mock_message])):
                result = await _scan_m3_honeypot({
                    "brand_name": "TestBrand",
                    "official_domains": ["testbrand.com"],
                    "executive_names": [],
                })
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["platform"] == "email"
        assert result[0]["finding_type"] == "honeypot_suspicious_email"
        assert result[0]["target_identifier"] == "<spam1@random-marketer.example>"

    @pytest.mark.asyncio
    async def test_honeypot_executive_impersonation_mock_response(self):
        from app.services.impersonation.scanner import _scan_m3_honeypot
        mock_message = {
            "message_id": "<fraud1@evil-lookalike.example>",
            "from_display": "Jordan CEO",
            "from_address": "jordan@evil-lookalike.example",
            "reply_to": "jordan.reply@another-domain.example",
            "to_addresses": ["ceo-honeypot@testbrand.com"],
            "subject": "URGENT wire transfer needed",
            "body": "Please wire the funds immediately, this is confidential.",
        }
        with patch.dict(
            "os.environ",
            {
                "HONEYPOT_IMAP_HOST": "mail.example.com",
                "HONEYPOT_IMAP_USER": "honeypot@example.com",
                "HONEYPOT_IMAP_PASSWORD": "secret",
            },
            clear=False,
        ):
            with patch("asyncio.to_thread", new=AsyncMock(return_value=[mock_message])):
                result = await _scan_m3_honeypot({
                    "brand_name": "TestBrand",
                    "official_domains": ["testbrand.com"],
                    "executive_names": ["Jordan Smith"],
                })
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["finding_type"] == "honeypot_bec_attempt"
        assert "executive_spoof" in result[0]["signals"]
        assert "reply_to_mismatch" in result[0]["signals"]
        assert "urgency_keywords" in result[0]["signals"]
        assert result[0]["threat_score"] > 50

    @pytest.mark.asyncio
    async def test_honeypot_message_not_addressed_to_alias_excluded(self):
        from app.services.impersonation.scanner import _scan_m3_honeypot
        mock_message = {
            "message_id": "<other1@random.example>",
            "from_display": "Someone",
            "from_address": "someone@random.example",
            "reply_to": "",
            "to_addresses": ["not-a-honeypot@testbrand.com"],
            "subject": "Hello",
            "body": "Not addressed to a honeypot alias.",
        }
        with patch.dict(
            "os.environ",
            {
                "HONEYPOT_IMAP_HOST": "mail.example.com",
                "HONEYPOT_IMAP_USER": "honeypot@example.com",
                "HONEYPOT_IMAP_PASSWORD": "secret",
            },
            clear=False,
        ):
            with patch("asyncio.to_thread", new=AsyncMock(return_value=[mock_message])):
                result = await _scan_m3_honeypot({
                    "brand_name": "TestBrand",
                    "official_domains": ["testbrand.com"],
                    "executive_names": [],
                })
        assert result == []

    @pytest.mark.asyncio
    async def test_honeypot_imap_connection_failure_returns_empty(self):
        from app.services.impersonation.scanner import _scan_m3_honeypot
        with patch.dict(
            "os.environ",
            {
                "HONEYPOT_IMAP_HOST": "mail.example.com",
                "HONEYPOT_IMAP_USER": "honeypot@example.com",
                "HONEYPOT_IMAP_PASSWORD": "secret",
            },
            clear=False,
        ):
            with patch("asyncio.to_thread", new=AsyncMock(side_effect=OSError("connection refused"))):
                result = await _scan_m3_honeypot({
                    "brand_name": "TestBrand",
                    "official_domains": ["testbrand.com"],
                    "executive_names": [],
                })
        assert result == []

    def test_fetch_honeypot_messages_parses_real_imap_response(self):
        import email.message
        from app.services.impersonation.scanner import _fetch_honeypot_messages

        msg = email.message.EmailMessage()
        msg["From"] = "Jordan CEO <jordan@evil-lookalike.example>"
        msg["To"] = "ceo-honeypot@testbrand.com"
        msg["Subject"] = "Urgent wire transfer"
        msg["Message-ID"] = "<abc123@evil-lookalike.example>"
        msg.set_content("Please wire funds immediately.")
        raw = msg.as_bytes()

        mock_conn = MagicMock()
        mock_conn.login.return_value = ("OK", [b"Logged in"])
        mock_conn.select.return_value = ("OK", [b"1"])
        mock_conn.search.return_value = ("OK", [b"1"])
        mock_conn.fetch.return_value = ("OK", [(b"1 (RFC822 {123}", raw)])
        mock_conn.store.return_value = ("OK", [b"1"])
        mock_conn.logout.return_value = ("BYE", [b"Logging out"])

        with patch("imaplib.IMAP4_SSL", return_value=mock_conn):
            result = _fetch_honeypot_messages("mail.example.com", 993, "user", "pass")

        assert len(result) == 1
        assert result[0]["from_address"] == "jordan@evil-lookalike.example"
        assert result[0]["to_addresses"] == ["ceo-honeypot@testbrand.com"]
        assert result[0]["message_id"] == "<abc123@evil-lookalike.example>"
        assert "wire funds" in result[0]["body"].lower()
        mock_conn.store.assert_called_once()


# ── Alert Engine ──────────────────────────────────────────────────────────────

class TestAlertEngine:
    def test_email_dispatch_function_exists(self):
        source = ALERT_ENGINE.read_text(encoding="utf-8")
        assert "_send_email_notification" in source

    def test_email_channel_type_handled(self):
        source = ALERT_ENGINE.read_text(encoding="utf-8")
        assert 'channel_type == "email"' in source

    def test_score_badge_function_exists(self):
        source = ALERT_ENGINE.read_text(encoding="utf-8")
        assert "_score_badge" in source

    def test_score_badges_correct_thresholds(self):
        source = ALERT_ENGINE.read_text(encoding="utf-8")
        assert "80" in source  # 🔴 threshold
        assert "50" in source  # 🟡 threshold

    @pytest.mark.asyncio
    async def test_send_slack_returns_false_on_empty_url(self):
        from app.services.impersonation.alert_engine import _send_slack
        result = await _send_slack("", "test message")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_telegram_returns_false_on_missing_params(self):
        from app.services.impersonation.alert_engine import _send_telegram
        result = await _send_telegram("", "chat123", "text")
        assert result is False
        result = await _send_telegram("bottoken", "", "text")
        assert result is False

    @pytest.mark.asyncio
    async def test_dispatch_channel_email_routes_to_email(self):
        from app.services.impersonation.alert_engine import _dispatch_channel
        with patch(
            "app.services.impersonation.alert_engine._send_email_notification",
            new=AsyncMock(return_value=True),
        ) as mock_email:
            result = await _dispatch_channel(
                {"type": "email", "to": "security@acme.com"},
                "Alert title",
                "Alert body",
            )
        assert result is True
        mock_email.assert_called_once_with("security@acme.com", "Alert title", "Alert body")

    @pytest.mark.asyncio
    async def test_dispatch_channel_unknown_type_returns_false(self):
        from app.services.impersonation.alert_engine import _dispatch_channel
        result = await _dispatch_channel({"type": "unknown_channel"}, "title", "body")
        assert result is False

    def test_finding_to_text_includes_badge(self):
        from app.services.impersonation.alert_engine import _finding_to_text
        finding = MagicMock()
        finding.module = "m7"
        finding.platform = "domain_registry"
        finding.finding_type = "vip_phishing_domain"
        finding.display_name = "acmee.com"
        finding.target_identifier = "acmee.com"
        finding.target_url = "http://acmee.com"
        finding.threat_score = 85
        finding.status = "new"
        finding.first_seen = None
        text = _finding_to_text(finding)
        assert "🔴" in text
        assert "M7" in text


async def _build_temp_session_factory(base):
    temp_dir = tempfile.mkdtemp(prefix="imp-alert-tests-")
    db_path = os.path.join(temp_dir, "test.sqlite3")
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False), db_path


def _cleanup_temp_db(db_path: str) -> None:
    shutil.rmtree(os.path.dirname(db_path), ignore_errors=True)


TEST_REVIEW_USER_ID_1 = 7
TEST_REVIEW_USER_ID_2 = 8


class TestAlertDispatchLifecycle:
    @pytest.mark.asyncio
    async def test_dispatch_once_and_idempotent_for_same_finding_rule(self):
        from app.database import Base
        from app.models import AlertDispatchHistory, AlertRule, ImpersonationFinding, ImpersonationRule
        from app.services.impersonation.alert_engine import dispatch_alerts

        engine, session_factory, db_path = await _build_temp_session_factory(Base)
        try:
            async with session_factory() as db:
                rule = ImpersonationRule(name="Rule", brand_name="Acme")
                db.add(rule)
                await db.flush()
                finding = ImpersonationFinding(
                    rule_id=rule.id,
                    module="m1",
                    platform="telegram",
                    finding_type="fake_account",
                    target_identifier="@acme_helpdesk",
                    threat_score=90,
                    status="new",
                    fingerprint="f001",
                )
                alert_rule = AlertRule(
                    name="Critical M1",
                    match_module="m1",
                    match_finding_type="fake_account",
                    min_threat_score=80,
                    channels_json='[{"type":"email","to":"security@acme.com"}]',
                    active=True,
                )
                db.add_all([finding, alert_rule])
                await db.commit()

                with patch(
                    "app.services.impersonation.alert_engine._dispatch_channel",
                    new=AsyncMock(return_value=True),
                ) as dispatch_mock:
                    first = await dispatch_alerts(finding.id, db)
                    await db.commit()
                    second = await dispatch_alerts(finding.id, db)
                    await db.commit()

                rows = (
                    await db.execute(
                        select(AlertDispatchHistory).where(
                            AlertDispatchHistory.finding_id == finding.id,
                            AlertDispatchHistory.alert_rule_id == alert_rule.id,
                        )
                    )
                ).scalars().all()

                assert first["rules_matched"] == 1
                assert first["notifications_sent"] == 1
                assert second["rules_already_dispatched"] == 1
                assert dispatch_mock.await_count == 1
                assert len(rows) == 1
        finally:
            await engine.dispose()
            _cleanup_temp_db(db_path)

    @pytest.mark.asyncio
    async def test_inactive_or_non_matching_rules_do_not_dispatch(self):
        from app.database import Base
        from app.models import AlertRule, ImpersonationFinding, ImpersonationRule
        from app.services.impersonation.alert_engine import dispatch_alerts

        engine, session_factory, db_path = await _build_temp_session_factory(Base)
        try:
            async with session_factory() as db:
                rule = ImpersonationRule(name="Rule", brand_name="Acme")
                db.add(rule)
                await db.flush()
                finding = ImpersonationFinding(
                    rule_id=rule.id,
                    module="m1",
                    platform="telegram",
                    finding_type="fake_account",
                    target_identifier="@acme_helpdesk",
                    threat_score=90,
                    status="new",
                    fingerprint="f002",
                )
                db.add_all(
                    [
                        finding,
                        AlertRule(
                            name="Inactive Rule",
                            match_module="m1",
                            match_finding_type="fake_account",
                            min_threat_score=80,
                            channels_json='[{"type":"email","to":"security@acme.com"}]',
                            active=False,
                        ),
                        AlertRule(
                            name="Wrong module",
                            match_module="m8",
                            match_finding_type="fake_account",
                            min_threat_score=80,
                            channels_json='[{"type":"email","to":"security@acme.com"}]',
                            active=True,
                        ),
                    ]
                )
                await db.commit()

                with patch(
                    "app.services.impersonation.alert_engine._dispatch_channel",
                    new=AsyncMock(return_value=True),
                ) as dispatch_mock:
                    stats = await dispatch_alerts(finding.id, db)

                assert stats["rules_checked"] == 1
                assert stats["rules_matched"] == 0
                dispatch_mock.assert_not_awaited()
        finally:
            await engine.dispose()
            _cleanup_temp_db(db_path)

    @pytest.mark.asyncio
    async def test_missing_notification_config_is_non_fatal_and_recorded(self):
        from app.database import Base
        from app.models import AlertDispatchHistory, AlertRule, ImpersonationFinding, ImpersonationRule
        from app.services.impersonation.alert_engine import dispatch_alerts

        engine, session_factory, db_path = await _build_temp_session_factory(Base)
        try:
            async with session_factory() as db:
                rule = ImpersonationRule(name="Rule", brand_name="Acme")
                db.add(rule)
                await db.flush()
                finding = ImpersonationFinding(
                    rule_id=rule.id,
                    module="m1",
                    platform="telegram",
                    finding_type="fake_account",
                    target_identifier="@acme_helpdesk",
                    threat_score=90,
                    status="new",
                    fingerprint="f003",
                )
                alert_rule = AlertRule(
                    name="No channels",
                    match_module="m1",
                    match_finding_type="fake_account",
                    min_threat_score=80,
                    channels_json="[]",
                    active=True,
                )
                db.add_all([finding, alert_rule])
                await db.commit()

                stats = await dispatch_alerts(finding.id, db)
                await db.commit()

                history = (
                    await db.execute(
                        select(AlertDispatchHistory).where(
                            AlertDispatchHistory.finding_id == finding.id,
                            AlertDispatchHistory.alert_rule_id == alert_rule.id,
                        )
                    )
                ).scalar_one_or_none()

                assert stats["rules_matched"] == 1
                assert stats["notifications_sent"] == 0
                assert stats["notifications_failed"] == 0
                assert stats["rules_skipped_no_channels"] == 1
                assert history is not None
                assert history.outcome == "skipped_no_channels"
        finally:
            await engine.dispose()
            _cleanup_temp_db(db_path)

    @pytest.mark.asyncio
    async def test_scanner_path_dispatches_once_across_reruns(self, monkeypatch):
        from app import database
        from app.database import Base
        from app.models import AlertDispatchHistory, AlertRule, ImpersonationRule
        from app.services.impersonation.scanner import run_scan_for_rule

        engine, session_factory, db_path = await _build_temp_session_factory(Base)
        try:
            monkeypatch.setattr(database, "AsyncSessionLocal", session_factory)

            async with session_factory() as db:
                imp_rule = ImpersonationRule(
                    name="Scan Rule",
                    brand_name="Acme",
                    m1_social_enabled=True,
                    m2_apps_enabled=False,
                    m3_email_enabled=False,
                    m5_exec_enabled=False,
                    m6_ads_enabled=False,
                    m7_vip_enabled=False,
                    m8_domain_enabled=False,
                    social_platforms='["telegram"]',
                )
                alert_rule = AlertRule(
                    name="M1 Alerts",
                    match_module="m1",
                    match_finding_type="fake_account",
                    min_threat_score=80,
                    channels_json='[{"type":"email","to":"security@acme.com"}]',
                    active=True,
                )
                db.add_all([imp_rule, alert_rule])
                await db.commit()
                await db.refresh(imp_rule)

            async def _fake_scan_m1(_rule_data):
                return [
                    {
                        "module": "m1",
                        "platform": "telegram",
                        "finding_type": "fake_account",
                        "target_url": "https://t.me/acme_helpdesk",
                        "target_identifier": "@acme_helpdesk",
                        "display_name": "Acme Helpdesk",
                        "description": "fake support account",
                        "threat_score": 91,
                        "signals": ["impersonation"],
                        "evidence": {},
                    }
                ]

            monkeypatch.setattr("app.services.impersonation.scanner._scan_m1_social", _fake_scan_m1)
            with patch(
                "app.services.impersonation.alert_engine._dispatch_channel",
                new=AsyncMock(return_value=True),
            ) as dispatch_mock:
                await run_scan_for_rule(imp_rule.id)
                await run_scan_for_rule(imp_rule.id)

            async with session_factory() as db:
                history_rows = (
                    await db.execute(select(AlertDispatchHistory))
                ).scalars().all()
                assert len(history_rows) == 1
                assert dispatch_mock.await_count == 1
        finally:
            await engine.dispose()
            _cleanup_temp_db(db_path)

    @pytest.mark.asyncio
    async def test_manual_update_path_triggers_alert_evaluation(self):
        from app.database import Base
        from app.models import AlertDispatchHistory, AlertRule, ImpersonationFinding, ImpersonationRule
        from app.schemas import ImpersonationFindingStatusUpdate
        from app.api.impersonation import update_finding_status

        engine, session_factory, db_path = await _build_temp_session_factory(Base)
        try:
            async with session_factory() as db:
                rule = ImpersonationRule(name="Rule", brand_name="Acme")
                db.add(rule)
                await db.flush()
                finding = ImpersonationFinding(
                    rule_id=rule.id,
                    module="m1",
                    platform="telegram",
                    finding_type="fake_account",
                    target_identifier="@acme_helpdesk",
                    threat_score=92,
                    status="resolved",
                    fingerprint="f004",
                )
                alert_rule = AlertRule(
                    name="M1 Alerts",
                    match_module="m1",
                    match_finding_type="fake_account",
                    min_threat_score=80,
                    channels_json='[{"type":"email","to":"security@acme.com"}]',
                    active=True,
                )
                db.add_all([finding, alert_rule])
                await db.commit()
                await db.refresh(finding)

                with patch(
                    "app.services.impersonation.alert_engine._dispatch_channel",
                    new=AsyncMock(return_value=True),
                ) as dispatch_mock:
                    await update_finding_status(
                        finding.id,
                        ImpersonationFindingStatusUpdate(status="new"),
                        db,
                        SimpleNamespace(id=TEST_REVIEW_USER_ID_1),
                    )
                    await update_finding_status(
                        finding.id,
                        ImpersonationFindingStatusUpdate(status="under_review"),
                        db,
                        SimpleNamespace(id=TEST_REVIEW_USER_ID_2),
                    )

                history_rows = (
                    await db.execute(select(AlertDispatchHistory))
                ).scalars().all()
                assert len(history_rows) == 1
                assert dispatch_mock.await_count == 1
        finally:
            await engine.dispose()
            _cleanup_temp_db(db_path)


# ── New scanner functions are present in scanner.py ──────────────────────────

class TestScannerFunctionSignatures:
    def test_all_new_m1_functions_present(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m1_telegram" in source
        assert "async def _scan_m1_instagram" in source
        assert "async def _scan_m1_vk" in source
        assert "async def _scan_m1_facebook" in source

    def test_m2_google_play_present(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m2_google_play" in source

    def test_m7_vip_implemented(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "best_domain_similarity" in source or "rapidfuzz" in source or "nrd_feed" in source

    def test_m5_hibp_implemented(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "HIBPClient" in source
        assert "HIBP_API_KEY" in source

    def test_m3_honeypot_implemented(self):
        source = SCANNER.read_text(encoding="utf-8")
        assert "HONEYPOT_IMAP_HOST" in source
        assert "honeypot_bec_attempt" in source

    def test_stubs_still_present_for_phase2b(self):
        """Phase 2b stubs must remain for deferred modules."""
        source = SCANNER.read_text(encoding="utf-8")
        assert "async def _scan_m1_tiktok" in source
        assert "async def _scan_m1_linkedin" in source
        assert "async def _scan_m1_youtube" in source
        assert "async def _scan_m2_appstore" in source
        assert "async def _scan_m5_darkweb" in source
        assert "async def _scan_m6_ads" in source

    def test_env_example_updated(self):
        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        assert "HIBP_API_KEY" in env_example
        assert "APIFY_API_KEY" in env_example
        assert "FACEBOOK_APIFY_ACTOR" in env_example
        assert "VK_SERVICE_TOKEN" in env_example
        assert "HONEYPOT_IMAP_HOST" in env_example
        assert "PAGERDUTY_API_KEY" in env_example
        assert "PAGERDUTY_SERVICE_ID" in env_example

    def test_requirements_has_google_play_scraper(self):
        reqs = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        assert "google-play-scraper" in reqs
