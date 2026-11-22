import pytest
from fastapi.testclient import TestClient

from app.api.auth import get_current_user
from app.main import app
from app.services.infrastructure_intelligence.traffic_evidence import (
    TrafficEvidenceError,
    analyze_traffic_evidence,
)


def test_documented_indicators_and_headers_are_unverified_leads():
    text = (
        "KTracking.reportConversion(0, 'lead');\n"
        "new KClickClient('tracker', 'token');\n"
        "new BinomClickAPI();\n"
        'Location: https://user:secret@tracker.example/click.php?key=private&amp;lp_type=js_redirect\n'
        "Location: /next?secret=value\n"
    )
    result = analyze_traffic_evidence(text)
    assert [item["rule"] for item in result["signals"]] == [
        "keitaro_tracking", "keitaro_php_client", "binom_click_api", "binom_js_redirect",
    ]
    assert [item["line"] for item in result["signals"]] == [1, 2, 3, 4]
    assert result["signals"][3]["hostname"] == "tracker.example"
    assert result["location_headers"] == [
        {"line": 4, "hostname": "tracker.example", "relative": False, "has_query": True},
        {"line": 5, "hostname": None, "relative": True, "has_query": True},
    ]
    assert all(item["documentation_url"].startswith("https://docs.") for item in result["signals"])
    assert "private" not in str(result) and "secret" not in str(result)
    assert "not proof" in result["notice"]
    assert "does not rule out" in result["notice"]


def test_generic_terms_and_parameters_do_not_identify_a_vendor():
    result = analyze_traffic_evidence(
        "Keitaro Binom tracker click.php https://host.example/click.php?lp=1&subid=test"
    )
    assert result["signals"] == []


def test_relative_binom_pattern_and_result_limits():
    result = analyze_traffic_evidence(
        "/click.php?key=x&lp_type=js_redirect\n"
        + ("KTracking.update({});\n" * 101)
        + ("Location: /next\n" * 101)
    )
    assert result["signals_truncated"]
    assert len(result["signals"]) == 100
    assert result["signals"][0]["rule"] == "binom_js_redirect"
    assert result["signals"][-1]["line"] == 100
    assert result["location_headers_truncated"]
    assert len(result["location_headers"]) == 100
    assert analyze_traffic_evidence("/click.php?key=x&lp_type=js_redirect")["signals"][0]["hostname"] is None


def test_authenticated_api_no_store_and_validation():
    client = TestClient(app)
    path = "/api/v1/infra/analyze-traffic-evidence"
    assert client.post(path, json={"text": "KTracking.update("}).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: object()
    try:
        response = client.post(path, json={"text": "new BinomClickAPI();"})
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["signals"][0]["rule"] == "binom_click_api"
        for text in (" ", "secret" * 40000, "Location: javascript:alert(1)"):
            response = client.post(path, json={"text": text})
            assert response.status_code == 422
            assert response.headers["cache-control"] == "no-store"
            assert "secret" not in response.text
        response = client.post(path, content=b"not json", headers={"Content-Type": "application/json"})
        assert response.status_code == 422
        assert response.headers["cache-control"] == "no-store"
    finally:
        app.dependency_overrides.clear()


def test_excessive_url_query_does_not_return_partial_results():
    query = "&".join(f"p{i}=x" for i in range(101))
    with pytest.raises(TrafficEvidenceError) as exc:
        analyze_traffic_evidence(f"new BinomClickAPI(); https://example.com/click.php?{query}")
    assert "100 query parameters" in str(exc.value)
