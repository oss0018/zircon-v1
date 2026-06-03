from types import SimpleNamespace

from app.api.cti import indicator_matches_filters
from app.services.cti.attack_matrix import compute_attack_cell_state
from app.services.cti.ioc_extractor import extract_iocs
from app.services.cti.scorer import compute_ioc_score
from app.services.cti.sentinel import generate_sentinel_kql_rule
from app.services.cti.stix_factory import STIXFactory


def test_stix_factory_indicator_creation():
    stix_obj = STIXFactory.indicator(value="1.2.3.4", ioc_type="ip", confidence=88)
    assert stix_obj["type"] == "indicator"
    assert "ipv4-addr:value" in stix_obj["pattern"]
    assert stix_obj["confidence"] == 88


def test_ioc_extractor_refangs_inputs():
    parsed = extract_iocs("hxxp://evil[.]com/path from user@evil[.]com and 8[.]8[.]8[.]8")
    assert "http://evil.com/path" in parsed["urls"]
    assert "evil.com" in parsed["domains"]
    assert "user@evil.com" in parsed["emails"]
    assert "8.8.8.8" in parsed["ips"]


def test_ioc_scorer_false_positive_zeroes_score():
    score = compute_ioc_score(source_reputation=10, malware_confidence=10, exploitation_likelihood=10, siem_matches=2, is_false_positive=True)
    assert score["score"] == 0
    assert score["severity"] == "LOW"


def test_sentinel_kql_generation_contains_expected_table_and_field():
    kql = generate_sentinel_kql_rule("1.2.3.4", "ip")
    assert "SecurityAlert" in kql
    assert "IPAddress" in kql
    assert "1.2.3.4" in kql


def test_attack_matrix_state_computation():
    assert compute_attack_cell_state(used_by_actor=True, has_sentinel_rule=False, has_recent_activity=False) == "BLIND_SPOT"
    assert compute_attack_cell_state(used_by_actor=True, has_sentinel_rule=False, has_recent_activity=True) == "ACTIVE_BLIND_SPOT"
    assert compute_attack_cell_state(used_by_actor=True, has_sentinel_rule=True, has_recent_activity=False) == "COVERED_THREAT"
    assert compute_attack_cell_state(used_by_actor=False, has_sentinel_rule=True, has_recent_activity=False) == "PROTECTED"


def test_indicator_feed_filtering_logic():
    indicator = SimpleNamespace(ioc_type="ip", severity="HIGH", score=74, is_false_positive=False)
    assert indicator_matches_filters(indicator, ioc_type="ip", severity="HIGH", min_score=70, include_false_positive=False)
    assert not indicator_matches_filters(indicator, ioc_type="domain", severity="HIGH", min_score=70, include_false_positive=False)
    assert not indicator_matches_filters(indicator, ioc_type="ip", severity="CRITICAL", min_score=70, include_false_positive=False)

    fp = SimpleNamespace(ioc_type="ip", severity="HIGH", score=0, is_false_positive=True)
    assert not indicator_matches_filters(fp, ioc_type="ip", severity="HIGH", min_score=0, include_false_positive=False)
