import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from app.services.lookalike.threat_scorer import ThreatScorer
from app.services.lookalike.vt_enricher import enrich_vt


def _assert_null_vt(data: dict) -> None:
    assert data == {
        "vt_malicious": None,
        "vt_suspicious": None,
        "vt_harmless": None,
        "vt_undetected": None,
        "vt_engines": None,
        "vt_community_score": None,
        "vt_last_analysis_date": None,
    }


def test_enrich_vt_empty_api_key_returns_null_without_client_call():
    with patch("app.services.lookalike.vt_enricher.VirusTotalClient.search", new_callable=AsyncMock) as mocked:
        result = asyncio.run(enrich_vt("example.com", ""))
    _assert_null_vt(result)
    mocked.assert_not_awaited()


def test_enrich_vt_success_extracts_expected_fields():
    vt_payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 80,
                    "undetected": 19,
                },
                "last_analysis_results": {
                    "EngineA": {"category": "malicious"},
                    "EngineB": {"category": "suspicious"},
                    "EngineC": {"category": "harmless"},
                },
                "total_votes": {"malicious": 7, "harmless": 2},
                "last_analysis_date": 1700000000,
            }
        }
    }
    with patch("app.services.lookalike.vt_enricher.VirusTotalClient.search", new_callable=AsyncMock) as mocked:
        mocked.return_value = vt_payload
        result = asyncio.run(enrich_vt("example.com", "k"))

    assert result["vt_malicious"] == 2
    assert result["vt_suspicious"] == 1
    assert result["vt_harmless"] == 80
    assert result["vt_undetected"] == 19
    assert json.loads(result["vt_engines"]) == ["EngineA", "EngineB"]
    assert result["vt_community_score"] == 5
    assert result["vt_last_analysis_date"] == datetime.fromtimestamp(1700000000, tz=timezone.utc)
    mocked.assert_awaited_once_with("example.com", query_type="domain")


def test_enrich_vt_api_error_returns_null_without_raising():
    with patch("app.services.lookalike.vt_enricher.VirusTotalClient.search", new_callable=AsyncMock) as mocked:
        mocked.return_value = {"error": "bad key"}
        result = asyncio.run(enrich_vt("example.com", "k"))
    _assert_null_vt(result)


def test_threat_scorer_vt_detected_signal_for_malicious():
    scorer = ThreatScorer()
    score, _, signals = scorer.score({"vt_malicious": 1, "vt_suspicious": 0})
    assert "S21_vt_detected" in signals
    assert score >= 15
