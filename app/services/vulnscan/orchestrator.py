import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models import VSScan, VSScanTarget, VSFinding
from app.services.vulnscan.alerts import dispatch_severe_scan_alert
from app.services.vulnscan.normalizer import FindingDeduplicator, FindingNormalizer
from app.services.vulnscan.remediation import RemediationEngine
from app.services.vulnscan.scanners import (
    DNSSecScanner,
    HeaderScanner,
    NiktoScanner,
    NmapScanner,
    NucleiScanner,
    OpenVASScanner,
    TestSSLScanner,
    ZAPPassiveScanner,
)


PROFILE_SCANNERS = {
    "quick": ["headers", "dns_sec", "testssl", "nikto"],
    "standard": ["headers", "dns_sec", "testssl", "nikto", "nuclei", "zap_passive", "nmap"],
    "deep": ["headers", "dns_sec", "testssl", "nikto", "nuclei", "zap_passive", "openvas", "nmap"],
}

logger = logging.getLogger(__name__)


class VulnScanOrchestrator:
    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _target_parts(target_value: str) -> tuple[str, str, int | None]:
        value = target_value if target_value.startswith(("http://", "https://")) else f"https://{target_value}"
        parsed = urlparse(value)
        host = parsed.hostname or target_value
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return value, host, port

    async def _run_scanner(self, scanner: str, target: VSScanTarget, profile: str) -> list[dict]:
        target_url, host, port = self._target_parts(target.target_value)

        if scanner == "headers":
            return await HeaderScanner.scan(target_url)
        if scanner == "dns_sec":
            return await DNSSecScanner.scan(host)
        if scanner == "testssl":
            return await TestSSLScanner.scan(host, port)
        if scanner == "nikto":
            return await NiktoScanner.scan(target.target_value)
        if scanner == "nuclei":
            return await NucleiScanner.scan(target.target_value, profile)
        if scanner == "zap_passive":
            return await ZAPPassiveScanner.scan(target_url)
        if scanner == "openvas":
            return await OpenVASScanner.scan(target.target_value, profile)
        if scanner == "nmap":
            return await NmapScanner.scan(target.target_value, profile)
        return []

    async def run(self, scan_id: int) -> None:
        async with AsyncSessionLocal() as db:
            started_at = self._utcnow()
            scan = None
            try:
                scan_result = await db.execute(select(VSScan).where(VSScan.id == scan_id))
                scan = scan_result.scalar_one_or_none()
                if scan is None:
                    return

                target_result = await db.execute(select(VSScanTarget).where(VSScanTarget.id == scan.target_id))
                target = target_result.scalar_one_or_none()
                if target is None:
                    scan.status = "failed"
                    scan.error_message = "Target not found"
                    await db.commit()
                    return

                scanners = PROFILE_SCANNERS.get(scan.profile, PROFILE_SCANNERS["standard"])
                scan.status = "running"
                scan.started_at = started_at
                scan.scanners_used_json = json.dumps(scanners)
                scan.progress_pct = 5
                await db.commit()

                raw_findings: list[dict] = []
                if not scanners:
                    scan.progress_pct = 100
                    await db.commit()
                total_scanners = max(len(scanners), 1)
                for idx, scanner_name in enumerate(scanners, start=1):
                    try:
                        raw_findings.extend(await self._run_scanner(scanner_name, target, scan.profile))
                    except Exception:
                        logger.exception("Scanner %s failed for scan %s", scanner_name, scan_id)
                    finally:
                        scan.progress_pct = min(95, int((idx / total_scanners) * 90))
                        await db.commit()

                normalizer = FindingNormalizer()
                normalized_findings = normalizer.normalize(raw_findings, scan, target)

                deduplicator = FindingDeduplicator()
                new_findings = await deduplicator.filter_new(db, normalized_findings)

                for finding in new_findings:
                    RemediationEngine.enrich(finding)
                    db.add(finding)

                await db.flush()

                persisted_result = await db.execute(select(VSFinding).where(VSFinding.scan_id == scan.id))
                persisted = persisted_result.scalars().all()

                scan.findings_total = len(persisted)
                scan.findings_critical = sum(1 for f in persisted if f.severity == "CRITICAL")
                scan.findings_high = sum(1 for f in persisted if f.severity == "HIGH")
                scan.findings_medium = sum(1 for f in persisted if f.severity == "MEDIUM")
                scan.findings_low = sum(1 for f in persisted if f.severity == "LOW")
                scan.findings_info = sum(1 for f in persisted if f.severity == "INFO")
                scan.findings_new = len(new_findings)
                scan.findings_fixed = 0
                scan.findings_persisted = len(persisted)

                if scan.findings_critical:
                    scan.overall_risk = "CRITICAL"
                elif scan.findings_high:
                    scan.overall_risk = "HIGH"
                elif scan.findings_medium:
                    scan.overall_risk = "MEDIUM"
                elif scan.findings_low:
                    scan.overall_risk = "LOW"
                else:
                    scan.overall_risk = "INFO"

                completed_at = self._utcnow()
                scan.status = "completed"
                scan.progress_pct = 100
                scan.completed_at = completed_at
                scan.duration_ms = int((completed_at - started_at).total_seconds() * 1000)
                should_dispatch_severe_alert = False
                if (scan.findings_critical or scan.findings_high) and scan.severe_alert_processed_at is None:
                    scan.severe_alert_processed_at = completed_at
                    should_dispatch_severe_alert = True
                await db.commit()

                if should_dispatch_severe_alert:
                    try:
                        await dispatch_severe_scan_alert(scan, target, persisted)
                    except Exception:
                        logger.exception("Vulnerability scan severe alert failed for scan %s", scan_id)

            except Exception as exc:
                logger.exception("Vulnerability scan %s failed", scan_id)
                if scan is not None:
                    scan.status = "failed"
                    scan.error_message = str(exc)
                    scan.completed_at = self._utcnow()
                    await db.commit()
