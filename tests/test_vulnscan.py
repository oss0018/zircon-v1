import json


def test_vulnscan_models_importable():
    from app.models import VSScanTarget, VSScan, VSFinding, VSReport, VSCustomTemplate

    assert VSScanTarget.__tablename__ == "vs_scan_targets"
    assert VSScan.__tablename__ == "vs_scans"
    assert VSFinding.__tablename__ == "vs_findings"
    assert VSReport.__tablename__ == "vs_reports"
    assert VSCustomTemplate.__tablename__ == "vs_custom_templates"


def test_vulnscan_target_columns():
    from app.models import VSScanTarget

    cols = {c.name for c in VSScanTarget.__table__.columns}
    assert "name" in cols
    assert "target_type" in cols
    assert "target_value" in cols
    assert "tags_json" in cols
    assert "notify_channels_json" in cols


def test_vulnscan_scan_columns():
    from app.models import VSScan

    cols = {c.name for c in VSScan.__table__.columns}
    assert "target_id" in cols
    assert "profile" in cols
    assert "status" in cols
    assert "scanners_used_json" in cols
    assert "progress_pct" in cols


def test_vulnscan_orchestrator_importable():
    from app.services.vulnscan import VulnScanOrchestrator

    assert VulnScanOrchestrator() is not None


def test_vulnscan_router_importable_and_paths():
    from fastapi import APIRouter
    from app.api.vulnscan import router

    assert isinstance(router, APIRouter)
    paths = {r.path for r in router.routes}

    assert "/targets" in paths
    assert "/targets/{target_id}" in paths
    assert "/targets/{target_id}/scan" in paths
    assert "/scans" in paths
    assert "/scans/{scan_id}" in paths
    assert "/scans/{scan_id}/findings" in paths
    assert "/scans/{scan_id}/summary" in paths
    assert "/findings/{finding_id}" in paths
    assert "/findings/{finding_id}/status" in paths
    assert "/templates" in paths
    assert "/templates/{template_id}" in paths
    assert "/dashboard/summary" in paths


def test_normalizer_assigns_severity_and_fingerprint():
    from app.services.vulnscan.normalizer import FindingNormalizer

    class _Scan:
        id = 1

    class _Target:
        id = 2
        target_value = "https://example.com"

    raw = [
        {
            "scanner_source": "nuclei",
            "scanner_finding_id": "CVE-2021-44228",
            "title": "Test",
            "description": "Test finding",
            "finding_type": "CVE",
            "severity": "CRITICAL",
            "target_host": "example.com",
            "target_port": 443,
            "cve_ids_json": json.dumps(["CVE-2021-44228"]),
        }
    ]

    finding = FindingNormalizer().normalize(raw, _Scan(), _Target())[0]
    assert finding.severity_numeric == 5
    assert len(finding.fingerprint) == 64


def test_main_has_vulnscan_router_registration():
    from app.main import app

    paths = {route.path for route in app.routes}
    assert "/api/v1/vulnscan/targets" in paths
