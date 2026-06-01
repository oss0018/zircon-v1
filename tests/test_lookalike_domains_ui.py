from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = REPO_ROOT / 'app' / 'static' / 'index.html'
LOOKALIKE_JS = REPO_ROOT / 'app' / 'static' / 'js' / 'lookalike_domains.js'
LOOKALIKE_API = REPO_ROOT / 'app' / 'api' / 'lookalike.py'


def test_index_wires_lookalike_domains_page_into_spa():
    html = INDEX_HTML.read_text(encoding='utf-8')

    assert "/static/js/lookalike_domains.js" in html
    assert "page === 'lookalike-domains'" in html
    assert "x-data=\"lookalikeDomainsPage\"" in html
    assert "Look-alike Rule" in html
    assert "Trusted Domains" in html


def test_lookalike_domains_component_targets_expected_frontend_flows():
    js = LOOKALIKE_JS.read_text(encoding='utf-8')

    assert "Alpine.data('lookalikeDomainsPage'" in js
    assert "/lookalike/rules" in js
    assert "/lookalike/preview" in js
    assert "/lookalike/rules/${rule.id}/scan" in js
    assert "/lookalike/rules/${this.domainsFilters.ruleId}/domains" in js
    assert "/lookalike/domains/${domain.id}" in js
    assert "/lookalike/rules/${this.selectedDomain.rule_id}/domains/${this.selectedDomain.id}/enrich" in js
    assert "/lookalike/rules/${this.selectedDomain.rule_id}/alert" in js
    assert "/lookalike/rules/${this.selectedDomain.rule_id}/domains/${this.selectedDomain.id}/takedown" in js
    assert "drawerTab" in js
    assert "alert_threshold" in js
    assert "markFalsePositive" in js
    assert "markTrusted" in js
    assert "parseInt(this.ruleForm.brand_id, 10)" in js
    assert "Number.isInteger(payload.brand_id)" in js
    assert "this.brands = Array.isArray(response) ? response : []" in js


def test_lookalike_api_supports_ui_preview_and_fqdn_filtering():
    api_source = LOOKALIKE_API.read_text(encoding='utf-8')

    assert '@router.post("/preview")' in api_source
    assert 'class RulePreviewBody' in api_source
    assert 'fqdn: Optional[str] = Query(None)' in api_source
    assert 'LookalikeDomain.fqdn.ilike' in api_source
    assert 'alert_threshold' in api_source
    assert 'class AlertDispatchBody' in api_source
    assert 'watch_mode_enabled=body.watch_mode_enabled if body.watch_mode_enabled is not None else False' in api_source


def test_index_contains_phase2_drawer_tabs_and_actions():
    html = INDEX_HTML.read_text(encoding='utf-8')

    assert "Screenshot" in html
    assert "WHOIS" in html
    assert "GeoIP" in html
    assert "No screenshot captured yet — use Enrich to fetch" in html
    assert "Takedown Package" in html
    assert "Send Alert" in html
    assert "Alert Threshold (%)" in html
