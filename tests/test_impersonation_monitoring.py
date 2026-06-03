from pathlib import Path

from app.schemas import ImpersonationRuleOut


REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = REPO_ROOT / 'app' / 'static' / 'index.html'
IMPERSONATION_JS = REPO_ROOT / 'app' / 'static' / 'js' / 'impersonation.js'
IMPERSONATION_API = REPO_ROOT / 'app' / 'api' / 'impersonation.py'
SCANNER = REPO_ROOT / 'app' / 'services' / 'impersonation' / 'scanner.py'


def test_index_wires_impersonation_page_into_spa():
    html = INDEX_HTML.read_text(encoding='utf-8')

    assert "/static/js/impersonation.js" in html
    assert "page === 'impersonation-monitoring'" in html
    assert 'x-data="impersonationPage"' in html
    assert 'Overview' in html
    assert 'Findings' in html
    assert 'Rules' in html
    assert 'Takedowns' in html
    assert 'Add Rule' in html
    assert 'Scan Now' in html


def test_impersonation_frontend_targets_expected_api_flows():
    js = IMPERSONATION_JS.read_text(encoding='utf-8')

    assert "Alpine.data('impersonationPage'" in js
    assert "/impersonation/stats" in js
    assert "/impersonation/findings" in js
    assert "/impersonation/rules" in js
    assert "/impersonation/takedowns" in js
    assert "/impersonation/findings/export" in js
    assert "createTakedown" in js
    assert "moduleMeta" in js
    assert "scoreBadgeClass" in js


def test_impersonation_api_replaces_opensquat_proxy_with_new_endpoints():
    source = IMPERSONATION_API.read_text(encoding='utf-8')

    assert 'TAKEDOWN_CONTACTS' in source
    assert 'SOCIAL_TAKEDOWN_TEMPLATE' in source
    assert 'DOMAIN_TAKEDOWN_TEMPLATE' in source
    assert '@router.get("/rules", response_model=list[ImpersonationRuleOut])' in source
    assert '@router.get("/findings/export")' in source
    assert '@router.post("/rules/{rule_id}/scan", status_code=202)' in source
    assert '@router.post("/takedowns", response_model=TakedownRequestOut, status_code=201)' in source
    assert 'run_scan_for_rule' in source
    assert 'opensquat' not in source.lower()


def test_impersonation_schema_parses_json_backed_lists():
    rule = ImpersonationRuleOut.model_validate(
        {
            'id': 1,
            'brand_id': None,
            'name': 'Acme Rule',
            'brand_name': 'Acme',
            'brand_name_uk': '',
            'brand_name_ru': '',
            'official_domains': '["acme.com", "acme.ua"]',
            'official_developer_ids': '["com.acme.app"]',
            'executive_names': '["Jane Doe"]',
            'partner_domains': '["partner.acme.com"]',
            'trademark_name': 'Acme',
            'trademark_reg_no': '123',
            'org_name': 'Acme Inc',
            'contact_name': 'Jane Doe',
            'contact_email': 'security@acme.com',
            'contact_phone': '',
            'm1_social_enabled': True,
            'm2_apps_enabled': True,
            'm3_email_enabled': True,
            'm5_exec_enabled': True,
            'm6_ads_enabled': True,
            'm7_vip_enabled': True,
            'm8_domain_enabled': True,
            'social_platforms': '["telegram", "instagram"]',
            'min_impersonation_score': 40,
            'schedule_cron': '0 */6 * * *',
            'active': True,
            'last_scan_at': None,
            'findings_count': 0,
            'created_at': '2026-06-03T00:00:00Z',
            'updated_at': '2026-06-03T00:00:00Z',
        }
    )

    assert rule.official_domains == ['acme.com', 'acme.ua']
    assert rule.executive_names == ['Jane Doe']
    assert rule.social_platforms == ['telegram', 'instagram']


def test_scanner_stub_is_present_and_importable():
    source = SCANNER.read_text(encoding='utf-8')

    assert 'async def run_scan_for_rule(rule_id: int) -> dict:' in source
    assert '_make_fingerprint' in source
    assert 'Duplicate finding skipped' in source
    assert 'Social scan stub' in source
