import json
import asyncio
import os
import tempfile
from pathlib import Path

import dns.exception
import dns.rdatatype
import dns.resolver
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = REPO_ROOT / "app" / "static" / "index.html"
VULNSCAN_JS = REPO_ROOT / "app" / "static" / "js" / "vulnscan.js"


async def _build_temp_session_factory(base):
    fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False), db_path


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


def test_index_wires_vulnscan_page_into_spa():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "/static/js/vulnscan.js" in html
    assert "page === 'vulnscan'" in html
    assert 'x-data="vulnscanApp()"' in html
    assert "Vuln Scanner" in html


def test_vulnscan_component_targets_expected_frontend_flows():
    js = VULNSCAN_JS.read_text(encoding="utf-8")

    assert "Alpine.data('vulnscanApp'" in js
    assert "/vulnscan/dashboard/summary" in js
    assert "/vulnscan/targets?limit=100" in js
    assert "/vulnscan/scans?limit=30" in js
    assert "/vulnscan/targets/${this.launchModal.targetId}/scan" in js
    assert "/vulnscan/scans/${scan.id}/findings?limit=500" in js
    assert "/vulnscan/findings/${id}/status" in js
    assert "/vulnscan/templates?limit=100" in js
    assert "severityBadgeClass" in js
    assert "statusBadgeClass" in js
    assert "formatDuration" in js


def test_dnssec_scanner_emits_expected_weak_and_missing_findings(monkeypatch):
    from app.services.vulnscan.scanners import DNSSecScanner

    class _Txt:
        def __init__(self, value: str):
            self.strings = [value.encode("utf-8")]

    def _resolve(self, name, rdtype):  # noqa: ARG001
        if rdtype == "TXT" and name == "example.com":
            return [_Txt("v=spf1 include:_spf.example.com ~all")]
        if rdtype == "TXT" and name == "_dmarc.example.com":
            return [_Txt("v=DMARC1; p=none; rua=mailto:dmarc@example.com")]
        if rdtype == "TXT" and name == "default._domainkey.example.com":
            raise dns.resolver.NoAnswer()
        if rdtype == dns.rdatatype.DS:
            raise dns.resolver.NoAnswer()
        if rdtype == dns.rdatatype.CAA:
            raise dns.resolver.NoAnswer()
        return []

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)

    findings = asyncio.run(DNSSecScanner.scan("example.com"))
    finding_types = {f["finding_type"] for f in findings}

    assert "SPF_WEAK" in finding_types
    assert "DMARC_WEAK" in finding_types
    assert "DKIM_MISSING" in finding_types
    assert "DNSSEC_NOT_CONFIGURED" in finding_types
    assert "CAA_MISSING" in finding_types

    for finding in findings:
        assert finding.get("remediation_summary")
        references = json.loads(finding.get("references_json", "[]"))
        assert isinstance(references, list)
        assert references


def test_dnssec_scanner_handles_missing_records(monkeypatch):
    from app.services.vulnscan.scanners import DNSSecScanner

    def _resolve(self, name, rdtype):  # noqa: ARG001
        if rdtype == "TXT" and name in {"example.com", "_dmarc.example.com"}:
            raise dns.resolver.NoAnswer()
        if rdtype == "TXT" and name == "default._domainkey.example.com":
            return []
        if rdtype == dns.rdatatype.DS:
            return []
        if rdtype == dns.rdatatype.CAA:
            raise dns.resolver.NXDOMAIN()
        return []

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)

    findings = asyncio.run(DNSSecScanner.scan("example.com"))
    finding_types = {f["finding_type"] for f in findings}

    assert "SPF_MISSING" in finding_types
    assert "DMARC_MISSING" in finding_types
    assert "DKIM_MISSING" in finding_types
    assert "DNSSEC_NOT_CONFIGURED" in finding_types
    assert "CAA_MISSING" in finding_types


def test_dnssec_scanner_swallows_timeouts(monkeypatch):
    from app.services.vulnscan.scanners import DNSSecScanner

    def _resolve(self, name, rdtype):  # noqa: ARG001
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)

    findings = asyncio.run(DNSSecScanner.scan("example.com"))
    assert findings == []


def test_testssl_scanner_returns_tool_not_available_when_binary_missing(monkeypatch):
    from app.services.vulnscan.scanners import TestSSLScanner

    async def _missing(*args, **kwargs):  # noqa: ARG001
        raise FileNotFoundError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _missing)

    findings = asyncio.run(TestSSLScanner.scan("example.com", 443))
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "TOOL_NOT_AVAILABLE"
    assert findings[0]["title"] == "TestSSL not installed"


def test_testssl_scanner_parses_json_output(monkeypatch):
    from app.services.vulnscan.scanners import TestSSLScanner

    captured = {"json_path": None}

    class _Proc:
        returncode = 0

        async def wait(self):
            return self.returncode

        def kill(self):
            return None

    async def _spawn(*args, **kwargs):  # noqa: ARG001
        json_path = Path(args[2])
        captured["json_path"] = json_path
        json_path.write_text(
            json.dumps(
                [
                    {"id": "TLS1", "severity": "WARN", "finding": "TLS1 enabled", "ip": "127.0.0.1"},
                    {"id": "HEARTBLEED", "severity": "HIGH", "finding": "Heartbleed detected", "ip": "127.0.0.1"},
                    {"id": "cipher_order", "severity": "OK", "finding": "ok", "ip": "127.0.0.1"},
                ]
            ),
            encoding="utf-8",
        )
        return _Proc()

    monkeypatch.setattr("app.services.vulnscan.scanners.shutil.which", lambda name: "/usr/bin/testssl.sh" if name == "testssl.sh" else None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)

    findings = asyncio.run(TestSSLScanner.scan("example.com", 443))
    assert {f["finding_type"] for f in findings} == {"TLS_DEPRECATED_PROTOCOL", "HEARTBLEED"}
    assert all("references_json" in f for f in findings)
    assert not captured["json_path"].exists()


def test_nikto_scanner_parses_json_and_maps_keywords(monkeypatch):
    from app.services.vulnscan.scanners import NiktoScanner

    class _Proc:
        returncode = 0

        async def wait(self):
            return self.returncode

        def kill(self):
            return None

    monkeypatch.setattr("app.services.vulnscan.scanners.shutil.which", lambda name: "/usr/bin/nikto" if name == "nikto" else None)

    async def _spawn(*args, **kwargs):  # noqa: ARG001
        output_idx = args.index("-output") + 1
        Path(args[output_idx]).write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "id": "999986",
                            "msg": "Possible SQL injection in /search",
                            "uri": "/search",
                            "method": "GET",
                            "references": "https://example.org/advisory",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return _Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)
    findings = asyncio.run(NiktoScanner.scan("https://example.com"))

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "SQLI"
    refs = json.loads(findings[0]["references_json"])
    assert "https://cirt.net/nikto2" in refs
    assert "https://example.org/advisory" in refs


def test_nuclei_scanner_streams_and_deduplicates(monkeypatch):
    from app.services.vulnscan.scanners import NucleiScanner

    captured_cmd = {}

    class _Stdout:
        def __init__(self):
            self._lines = [
                b'{"template-id":"cve-test","info":{"name":"CVE Test","severity":"high","description":"desc","classification":{"cve-id":["CVE-2024-0001"],"cwe-id":["CWE-79"],"cvss-score":8.1},"reference":["https://ref"]},"matched-at":"https://example.com/a"}\n',
                b'{"template-id":"cve-test","info":{"name":"CVE Test","severity":"high","description":"desc","classification":{"cve-id":["CVE-2024-0001"]}},"matched-at":"https://example.com/a"}\n',
                b"not-json\n",
            ]

        async def readline(self):
            return self._lines.pop(0) if self._lines else b""

    class _Stderr:
        async def read(self):
            return b""

    class _Proc:
        returncode = 0

        def __init__(self):
            self.stdout = _Stdout()
            self.stderr = _Stderr()

        async def wait(self):
            return self.returncode

        def kill(self):
            return None

    async def _spawn(*args, **kwargs):  # noqa: ARG001
        captured_cmd["args"] = args
        return _Proc()

    monkeypatch.setattr("app.services.vulnscan.scanners.shutil.which", lambda name: "/usr/bin/nuclei" if name == "nuclei" else None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)

    findings = asyncio.run(NucleiScanner.scan("https://example.com", "quick"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_type"] == "CVE"
    assert finding["severity"] == "HIGH"
    assert json.loads(finding["cve_ids_json"]) == ["CVE-2024-0001"]
    assert "-tags" in captured_cmd["args"]


def test_nuclei_scanner_omits_tags_for_deep(monkeypatch):
    from app.services.vulnscan.scanners import NucleiScanner

    captured_cmd = {}

    class _Stdout:
        async def readline(self):
            return b""

    class _Stderr:
        async def read(self):
            return b""

    class _Proc:
        returncode = 0

        def __init__(self):
            self.stdout = _Stdout()
            self.stderr = _Stderr()

        async def wait(self):
            return self.returncode

        def kill(self):
            return None

    async def _spawn(*args, **kwargs):  # noqa: ARG001
        captured_cmd["args"] = args
        return _Proc()

    monkeypatch.setattr("app.services.vulnscan.scanners.shutil.which", lambda name: "/usr/bin/nuclei" if name == "nuclei" else None)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _spawn)

    findings = asyncio.run(NucleiScanner.scan("https://example.com", "deep"))
    assert findings == []
    assert "-tags" not in captured_cmd["args"]


def test_nuclei_scanner_returns_tool_not_available_when_binary_missing(monkeypatch):
    from app.services.vulnscan.scanners import NucleiScanner

    monkeypatch.setattr("app.services.vulnscan.scanners.shutil.which", lambda name: None)

    findings = asyncio.run(NucleiScanner.scan("https://example.com", "quick"))
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "TOOL_NOT_AVAILABLE"
    assert findings[0]["title"] == "Nuclei not installed"


@pytest.mark.asyncio
async def test_resync_vulnscan_scheduled_jobs_schedules_active_valid_targets(monkeypatch, caplog):
    from app import database
    from app.database import Base
    from app.models import VSScanTarget
    from app.services import scheduler

    engine, session_factory, db_path = await _build_temp_session_factory(Base)

    class _Job:
        def __init__(self, job_id):
            self.id = job_id

    try:
        async with session_factory() as db:
            db.add_all(
                [
                    VSScanTarget(
                        name="valid",
                        target_value="https://example.com",
                        schedule_cron="*/20 * * * *",
                        active=True,
                    ),
                    VSScanTarget(
                        name="invalid",
                        target_value="https://bad.example",
                        schedule_cron="bad cron",
                        active=True,
                    ),
                    VSScanTarget(
                        name="inactive",
                        target_value="https://inactive.example",
                        schedule_cron="*/15 * * * *",
                        active=False,
                    ),
                ]
            )
            await db.commit()

        monkeypatch.setattr(database, "AsyncSessionLocal", session_factory)
        added_jobs = {}
        removed_jobs = []
        existing_jobs = [_Job("vulnscan_target_999"), _Job("scan_monitored")]

        def _add_job(func, trigger, *args, **kwargs):
            added_jobs[kwargs["id"]] = {"func": func, "trigger": trigger, "kwargs": kwargs}

        monkeypatch.setattr(scheduler._scheduler, "add_job", _add_job)
        monkeypatch.setattr(scheduler._scheduler, "get_jobs", lambda: existing_jobs)
        monkeypatch.setattr(scheduler._scheduler, "remove_job", lambda job_id: removed_jobs.append(job_id))

        with caplog.at_level("WARNING"):
            await scheduler.resync_vulnscan_scheduled_jobs()

        assert set(added_jobs) == {"vulnscan_target_1"}
        assert added_jobs["vulnscan_target_1"]["kwargs"]["replace_existing"] is True
        assert removed_jobs == ["vulnscan_target_999"]
        assert "invalid cron" in caplog.text
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_run_vulnscan_target_scan_creates_scan_and_invokes_orchestrator(monkeypatch):
    from app import database
    from app.database import Base
    from app.models import VSScan, VSScanTarget
    from app.services import scheduler

    engine, session_factory, db_path = await _build_temp_session_factory(Base)

    called_scan_ids = []

    class _FakeOrchestrator:
        async def run(self, scan_id: int):
            called_scan_ids.append(scan_id)

    try:
        async with session_factory() as db:
            target = VSScanTarget(
                name="scheduled",
                target_value="https://example.com",
                default_profile="unsupported",
                schedule_cron="*/10 * * * *",
                active=True,
            )
            db.add(target)
            await db.commit()
            await db.refresh(target)
            target_id = target.id

        monkeypatch.setattr(database, "AsyncSessionLocal", session_factory)
        monkeypatch.setattr("app.services.vulnscan.VulnScanOrchestrator", _FakeOrchestrator)

        await scheduler._run_vulnscan_target_scan(target_id)

        async with session_factory() as db:
            scans = list((await db.execute(select(VSScan))).scalars().all())

        assert len(scans) == 1
        assert scans[0].target_id == target_id
        assert scans[0].profile == "standard"
        assert scans[0].comment == "Scheduled scan"
        assert called_scan_ids == [scans[0].id]
    finally:
        await engine.dispose()
        os.remove(db_path)


@pytest.mark.asyncio
async def test_run_vulnscan_target_scan_uses_valid_default_profile(monkeypatch):
    from app import database
    from app.database import Base
    from app.models import VSScan, VSScanTarget
    from app.services import scheduler

    engine, session_factory, db_path = await _build_temp_session_factory(Base)

    class _FakeOrchestrator:
        async def run(self, _scan_id: int):
            pass

    try:
        async with session_factory() as db:
            target = VSScanTarget(
                name="scheduled-quick",
                target_value="https://example.com",
                default_profile="quick",
                schedule_cron="*/10 * * * *",
                active=True,
            )
            db.add(target)
            await db.commit()
            await db.refresh(target)
            target_id = target.id

        monkeypatch.setattr(database, "AsyncSessionLocal", session_factory)
        monkeypatch.setattr("app.services.vulnscan.VulnScanOrchestrator", _FakeOrchestrator)

        await scheduler._run_vulnscan_target_scan(target_id)

        async with session_factory() as db:
            scan = (await db.execute(select(VSScan))).scalar_one()

        assert scan.profile == "quick"
    finally:
        await engine.dispose()
        os.remove(db_path)
