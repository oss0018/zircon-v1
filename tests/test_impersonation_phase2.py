"""
Tests for Phase 2 Impersonation Monitoring enhancements (TS-IMP-001 v2).

Covers:
- New database models (AlertRule, LegalTask, ThreatActor, ThreatActorProfile, SLA, AuditLogEntry)
- New Pydantic schemas
- New scanner stubs
- New API endpoints structure
- New frontend JS methods
- New service modules (alert_engine, evidence_generator, threat_actor_correlator)
"""
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODELS = REPO_ROOT / 'app' / 'models.py'
SCHEMAS = REPO_ROOT / 'app' / 'schemas.py'
IMPERSONATION_API = REPO_ROOT / 'app' / 'api' / 'impersonation.py'
SCANNER = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'scanner.py'
ALERT_ENGINE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'alert_engine.py'
EVIDENCE_GEN = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'evidence_generator.py'
CORRELATOR = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'threat_actor_correlator.py'
FINDINGS_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'findings_service.py'
TAKEDOWN_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'takedown_service.py'
RULES_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'rules_service.py'
ALERT_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'alert_service.py'
THREAT_ACTOR_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'threat_actor_service.py'
LEGAL_TASK_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'legal_task_service.py'
SLA_SERVICE = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'sla_service.py'
IMPERSONATION_JS = REPO_ROOT / 'app' / 'static' / 'js' / 'impersonation.js'
INDEX_HTML = REPO_ROOT / 'app' / 'static' / 'index.html'


# ── Model tests ───────────────────────────────────────────────────────────────

def test_phase2_models_are_importable():
    from app.models import (
        AlertRule,
        LegalTask,
        ThreatActor,
        ThreatActorProfile,
        ServiceLevelAgreement,
        AuditLogEntry,
    )
    assert AlertRule.__tablename__ == 'impersonation_alert_rules'
    assert LegalTask.__tablename__ == 'impersonation_legal_tasks'
    assert ThreatActor.__tablename__ == 'impersonation_threat_actors'
    assert ThreatActorProfile.__tablename__ == 'impersonation_threat_actor_profiles'
    assert ServiceLevelAgreement.__tablename__ == 'impersonation_slas'
    assert AuditLogEntry.__tablename__ == 'impersonation_audit_log'


def test_alert_rule_model_has_expected_columns():
    from app.models import AlertRule
    cols = {c.key for c in AlertRule.__table__.columns}
    assert 'name' in cols
    assert 'match_module' in cols
    assert 'match_finding_type' in cols
    assert 'min_threat_score' in cols
    assert 'channels_json' in cols
    assert 'active' in cols


def test_threat_actor_model_has_relationship_to_profile():
    from app.models import ThreatActor, ThreatActorProfile
    # Verify one-to-one relationship is declared
    assert hasattr(ThreatActor, 'profile')
    assert hasattr(ThreatActorProfile, 'actor')


def test_legal_task_model_columns():
    from app.models import LegalTask
    cols = {c.key for c in LegalTask.__table__.columns}
    assert 'finding_id' in cols
    assert 'takedown_id' in cols
    assert 'task_type' in cols
    assert 'status' in cols
    assert 'due_date' in cols
    assert 'external_ref' in cols


def test_sla_model_time_columns():
    from app.models import ServiceLevelAgreement
    cols = {c.key for c in ServiceLevelAgreement.__table__.columns}
    assert 'time_to_detect_min' in cols
    assert 'time_to_triage_min' in cols
    assert 'time_to_takedown_min' in cols
    assert 'time_to_resolve_min' in cols


def test_sla_policy_alias_exists():
    from app.models import SLAPolicy, ServiceLevelAgreement
    assert SLAPolicy is ServiceLevelAgreement


def test_audit_log_model_columns():
    from app.models import AuditLogEntry
    cols = {c.key for c in AuditLogEntry.__table__.columns}
    assert 'action' in cols
    assert 'entity_type' in cols
    assert 'entity_id' in cols
    assert 'old_value_json' in cols
    assert 'new_value_json' in cols


# ── Schema tests ──────────────────────────────────────────────────────────────

def test_phase2_schemas_are_importable():
    from app.schemas import (
        AlertRuleCreate,
        AlertRuleOut,
        AlertRuleUpdate,
        LegalTaskCreate,
        LegalTaskOut,
        LegalTaskUpdate,
        ThreatActorCreate,
        ThreatActorOut,
        ThreatActorUpdate,
        ThreatActorProfileCreate,
        ThreatActorProfileOut,
        ThreatActorProfileUpdate,
        ServiceLevelAgreementCreate,
        ServiceLevelAgreementOut,
        ServiceLevelAgreementUpdate,
        SLAPolicyOut,
        ImpersonationStatsOut,
        AuditLogEntryOut,
        EvidencePackageRequest,
    )
    # Just verify they import correctly
    assert AlertRuleCreate
    assert ThreatActorOut
    assert ServiceLevelAgreementCreate
    assert SLAPolicyOut
    assert ImpersonationStatsOut
    assert EvidencePackageRequest


def test_alert_rule_schema_defaults():
    from app.schemas import AlertRuleCreate
    rule = AlertRuleCreate(name='Test Rule', min_threat_score=80)
    assert rule.name == 'Test Rule'
    assert rule.min_threat_score == 80
    assert rule.active is True
    assert rule.channels_json == '[]'


def test_threat_actor_schema_parses_json_lists():
    from datetime import datetime
    from app.schemas import ThreatActorOut
    # ThreatActorOut field validators accept JSON strings for list fields
    actor = ThreatActorOut.model_validate({
        'id': 1,
        'name': 'APT-1',
        'description': '',
        'country_of_origin': 'Unknown',
        'known_aliases': '["alias1","alias2"]',
        'attack_patterns': '["T1566","T1190"]',
        'registrar_names': '["GoDaddy"]',
        'hosting_asns': '["AS12345"]',
        'registrant_emails': '["abuse@example.com"]',
        'payment_gateways': '[]',
        'linked_finding_ids': '[1,2,3]',
        'first_seen': '2026-01-01T00:00:00',
        'last_seen': '2026-06-01T00:00:00',
        'created_at': '2026-01-01T00:00:00',
        'updated_at': '2026-06-01T00:00:00',
    })
    assert actor.known_aliases == ['alias1', 'alias2']
    assert actor.attack_patterns == ['T1566', 'T1190']
    assert actor.linked_finding_ids == [1, 2, 3]
    assert actor.hosting_asns == ['AS12345']


def test_sla_schema_defaults():
    from app.schemas import ServiceLevelAgreementCreate
    sla = ServiceLevelAgreementCreate(name='Standard SLA')
    assert sla.time_to_triage_min == 240
    assert sla.time_to_takedown_min == 1440
    assert sla.time_to_resolve_min == 4320
    assert sla.active is True


def test_legal_task_schema_optional_ids():
    from app.schemas import LegalTaskCreate
    task = LegalTaskCreate(task_type='udrp', title='Test UDRP')
    assert task.finding_id is None
    assert task.takedown_id is None
    assert task.status == 'open'


def test_evidence_package_request_defaults():
    from app.schemas import EvidencePackageRequest
    req = EvidencePackageRequest()
    assert req.include_screenshot is True
    assert req.include_whois is True
    assert req.include_dns is True
    assert req.include_archive is True
    assert req.narrative == ''


def test_threat_actor_profile_schema_defaults():
    from app.schemas import ThreatActorProfileCreate
    profile = ThreatActorProfileCreate(actor_id=1)
    assert profile.tlp_level == 'amber'
    assert profile.motivation == ''
    assert profile.target_sectors == []


# ── Scanner stub tests ────────────────────────────────────────────────────────

def test_phase2_scanner_stubs_present():
    source = SCANNER.read_text(encoding='utf-8')
    assert 'async def _scan_m1_tiktok' in source
    assert 'async def _scan_m1_linkedin' in source
    assert 'async def _scan_m1_youtube' in source
    assert 'async def _scan_m2_appstore' in source
    assert 'async def _scan_m5_darkweb' in source
    assert 'async def _scan_m3_honeypot' in source
    assert 'async def _scan_m3_inbound_headers' in source


def test_scanner_orchestrator_calls_phase2_stubs():
    source = SCANNER.read_text(encoding='utf-8')
    # Orchestrator should reference the phase-2 stubs
    assert '_scan_m1_tiktok' in source
    assert '_scan_m1_linkedin' in source
    assert '_scan_m1_youtube' in source
    assert '_scan_m2_appstore' in source
    assert '_scan_m5_darkweb' in source
    assert '_scan_m3_honeypot' in source
    assert '_scan_m3_inbound_headers' in source


@pytest.mark.asyncio
async def test_phase2_scanner_stubs_return_empty_list():
    from app.services.impersonation.scanner import (
        _scan_m1_tiktok,
        _scan_m1_youtube,
        _scan_m2_appstore,
        _scan_m5_darkweb,
        _scan_m3_honeypot,
        _scan_m3_inbound_headers,
    )
    rule = {'brand_name': 'TestBrand', 'official_domains': ['testbrand.com'], 'executive_names': []}
    for stub in (
        _scan_m1_tiktok, _scan_m1_youtube,
        _scan_m2_appstore, _scan_m5_darkweb,
        _scan_m3_honeypot, _scan_m3_inbound_headers,
    ):
        result = await stub(rule)
        assert isinstance(result, list), f"{stub.__name__} should return a list"
        assert result == [], f"{stub.__name__} stub should return empty list"


@pytest.mark.asyncio
async def test_m1_linkedin_no_longer_a_stub():
    """_scan_m1_linkedin should gracefully no-op without APIFY_API_KEY /
    LINKEDIN_APIFY_ACTOR, but is no longer an unconditional stub (see
    TestScanM1Linkedin for full mocked-integration coverage)."""
    from app.services.impersonation.scanner import _scan_m1_linkedin
    from unittest.mock import patch

    with patch.dict('os.environ', {'APIFY_API_KEY': '', 'LINKEDIN_APIFY_ACTOR': ''}, clear=False):
        result = await _scan_m1_linkedin({
            'brand_name': 'TestBrand',
            'official_domains': ['testbrand.com'],
            'executive_names': [],
        })
    assert result == []


@pytest.mark.asyncio
async def test_m1_linkedin_handles_missing_brand_name_in_noop_paths():
    from app.services.impersonation.scanner import _scan_m1_linkedin
    from unittest.mock import patch

    with patch.dict('os.environ', {'APIFY_API_KEY': '', 'LINKEDIN_APIFY_ACTOR': ''}, clear=False):
        result = await _scan_m1_linkedin({
            'executive_names': [],
        })
    assert result == []


# ── API endpoint tests ────────────────────────────────────────────────────────

def test_phase2_api_endpoints_present():
    source = IMPERSONATION_API.read_text(encoding='utf-8')
    # Alert rules
    assert '@router.get("/alert-rules"' in source
    assert '@router.post("/alert-rules"' in source
    assert '@router.put("/alert-rules/{rule_id}"' in source
    assert '@router.delete("/alert-rules/{rule_id}"' in source
    # Evidence package
    assert '@router.post("/takedowns/{takedown_id}/generate-evidence-package")' in source
    assert '@router.post("/takedowns/{takedown_id}/generate-evidence")' in source
    # Threat actors
    assert '@router.get("/threat-actors"' in source
    assert '@router.post("/threat-actors"' in source
    assert '@router.post("/threat-actors/{actor_id}/correlate")' in source
    # Threat actor profiles
    assert '@router.post("/threat-actors/{actor_id}/profile"' in source
    assert '@router.get("/threat-actors/{actor_id}/profile"' in source
    assert '@router.put("/threat-actors/{actor_id}/profile"' in source
    # Legal tasks
    assert '@router.get("/legal-tasks"' in source
    assert '@router.post("/legal-tasks"' in source
    # SLAs
    assert '@router.get("/slas"' in source
    assert '@router.post("/slas"' in source
    # Audit log
    assert '@router.get("/audit-log"' in source


def test_phase2_api_imports_phase2_models():
    source = IMPERSONATION_API.read_text(encoding='utf-8')
    assert 'AlertRule' in source
    assert 'LegalTask' in source
    assert 'ThreatActor' in source
    assert 'ThreatActorProfile' in source
    assert 'ServiceLevelAgreement' in source
    assert 'AuditLogEntry' in source
    assert 'EvidencePackageRequest' in source


# ── Service module tests ──────────────────────────────────────────────────────

def test_alert_engine_file_exists():
    assert ALERT_ENGINE.exists(), "alert_engine.py not found"


def test_alert_engine_has_dispatch_function():
    source = ALERT_ENGINE.read_text(encoding='utf-8')
    assert 'async def dispatch_alerts' in source
    assert '_send_slack' in source
    assert '_send_pagerduty' in source
    assert '_send_teams' in source
    assert '_send_telegram' in source
    assert '_rule_matches' in source


def test_evidence_generator_file_exists():
    assert EVIDENCE_GEN.exists(), "evidence_generator.py not found"


def test_evidence_generator_has_build_function():
    source = EVIDENCE_GEN.read_text(encoding='utf-8')
    assert 'async def build_evidence_package' in source
    assert '_urlscan_submit' in source
    assert '_whois_lookup' in source
    assert '_dns_resolve' in source
    assert '_archive_check' in source
    assert '_http_headers_snapshot' in source


def test_threat_actor_correlator_file_exists():
    assert CORRELATOR.exists(), "threat_actor_correlator.py not found"


def test_threat_actor_correlator_has_correlate_function():
    source = CORRELATOR.read_text(encoding='utf-8')
    assert 'async def correlate_finding' in source
    assert 'async def link_finding_to_actor' in source
    assert '_extract_signals' in source
    assert '_score_overlap' in source


def test_phase2_service_layer_files_exist():
    for path in (
        FINDINGS_SERVICE,
        TAKEDOWN_SERVICE,
        RULES_SERVICE,
        ALERT_SERVICE,
        THREAT_ACTOR_SERVICE,
        LEGAL_TASK_SERVICE,
        SLA_SERVICE,
    ):
        assert path.exists(), f"{path.name} not found"


def test_phase2_service_layer_has_expected_functions():
    service_sources = {
        FINDINGS_SERVICE: ["async def list_findings", "async def update_finding_status"],
        TAKEDOWN_SERVICE: ["async def list_takedowns", "async def update_takedown"],
        RULES_SERVICE: ["async def list_rules", "async def get_rule_or_404"],
        ALERT_SERVICE: ["async def list_alert_rules", "async def dispatch_for_finding"],
        THREAT_ACTOR_SERVICE: ["async def list_threat_actors", "async def correlate_actor_findings"],
        LEGAL_TASK_SERVICE: ["async def list_legal_tasks", "async def get_legal_task_or_404"],
        SLA_SERVICE: ["async def list_slas", "def compute_sla_compliance"],
    }
    for path, expected_snippets in service_sources.items():
        source = path.read_text(encoding='utf-8')
        for snippet in expected_snippets:
            assert snippet in source, f"{snippet} missing in {path.name}"


# ── Frontend tests ────────────────────────────────────────────────────────────

def test_phase2_frontend_tabs_in_html():
    html = INDEX_HTML.read_text(encoding='utf-8')
    assert "Alert Rules" in html
    assert "Threat Actors" in html
    assert "Legal Tasks" in html
    assert "SLA" in html
    assert "changeTab('alert-rules')" in html
    assert "changeTab('threat-actors')" in html
    assert "changeTab('legal-tasks')" in html
    assert "changeTab('sla')" in html


def test_phase2_frontend_tab_panels_in_html():
    html = INDEX_HTML.read_text(encoding='utf-8')
    assert "activeTab === 'alert-rules'" in html
    assert "activeTab === 'threat-actors'" in html
    assert "activeTab === 'legal-tasks'" in html
    assert "activeTab === 'sla'" in html


def test_phase2_frontend_js_methods():
    js = IMPERSONATION_JS.read_text(encoding='utf-8')
    # Alert rules
    assert 'loadAlertRules' in js
    assert 'saveAlertRule' in js
    assert 'deleteAlertRule' in js
    assert 'openAlertRuleForm' in js
    assert 'resetAlertRuleForm' in js
    # Threat actors
    assert 'loadThreatActors' in js
    assert 'saveThreatActor' in js
    assert 'deleteThreatActor' in js
    assert 'correlateActor' in js
    assert 'toggleActor' in js
    # Legal tasks
    assert 'loadLegalTasks' in js
    assert 'saveLegalTask' in js
    assert 'deleteLegalTask' in js
    # SLA
    assert 'loadSlas' in js
    assert 'saveSla' in js
    assert 'deleteSla' in js
    assert 'slaMinutesToLabel' in js


def test_phase2_frontend_api_endpoints_referenced():
    js = IMPERSONATION_JS.read_text(encoding='utf-8')
    assert '/impersonation/alert-rules' in js
    assert '/impersonation/threat-actors' in js
    assert '/impersonation/legal-tasks' in js
    assert '/impersonation/slas' in js


def test_phase2_frontend_state_variables():
    js = IMPERSONATION_JS.read_text(encoding='utf-8')
    assert 'alertRules:' in js
    assert 'alertRuleForm:' in js
    assert 'threatActors:' in js
    assert 'threatActorForm:' in js
    assert 'legalTasks:' in js
    assert 'legalTaskForm:' in js
    assert 'slas:' in js
    assert 'slaForm:' in js
