import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import VSFinding, VSScan, VSScanTarget


class FindingNormalizer:
    SEVERITY_MAP = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    def normalize(
        self,
        raw_findings: list[dict],
        scan: VSScan,
        target: VSScanTarget,
    ) -> list[VSFinding]:
        now = self._utcnow()
        findings: list[VSFinding] = []

        for raw in raw_findings:
            severity = str(raw.get("severity", "INFO")).upper()
            severity_numeric = self.SEVERITY_MAP.get(severity, 1)
            target_port = raw.get("target_port")
            target_host = str(raw.get("target_host") or target.target_value)
            fingerprint_input = (
                f"{raw.get('scanner_finding_id', '')}|{target_host}|"
                f"{str(target_port or '')}|{raw.get('finding_type', '')}"
            )
            fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()

            finding = VSFinding(
                scan_id=scan.id,
                target_id=target.id,
                scanner_source=str(raw.get("scanner_source", "unknown"))[:30],
                scanner_finding_id=str(raw.get("scanner_finding_id", ""))[:255],
                title=str(raw.get("title", "Unnamed finding")),
                description=str(raw.get("description", "")),
                finding_type=str(raw.get("finding_type", "MISCONFIGURATION"))[:50],
                owasp_category=raw.get("owasp_category"),
                severity=severity,
                severity_numeric=severity_numeric,
                cvss_score=raw.get("cvss_score"),
                cvss_vector=str(raw.get("cvss_vector", "")),
                cve_ids_json=str(raw.get("cve_ids_json", "[]")),
                cwe_ids_json=str(raw.get("cwe_ids_json", "[]")),
                wasc_id=raw.get("wasc_id"),
                target_url=str(raw.get("target_url", target.target_value)),
                target_host=target_host[:512],
                target_ip=raw.get("target_ip"),
                target_port=target_port,
                affected_parameter=raw.get("affected_parameter"),
                request_excerpt=raw.get("request_excerpt"),
                response_excerpt=raw.get("response_excerpt"),
                evidence=raw.get("evidence"),
                curl_command=raw.get("curl_command"),
                remediation_summary=str(raw.get("remediation_summary", "")),
                remediation_steps_json=str(raw.get("remediation_steps_json", "[]")),
                remediation_effort=str(raw.get("remediation_effort", "MEDIUM")),
                patch_available=bool(raw.get("patch_available", False)),
                patch_url=raw.get("patch_url"),
                references_json=str(raw.get("references_json", "[]")),
                status=str(raw.get("status", "new")),
                fingerprint=fingerprint,
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
            )
            findings.append(finding)

        return findings


class FindingDeduplicator:
    async def filter_new(self, db: AsyncSession, findings: list[VSFinding]) -> list[VSFinding]:
        if not findings:
            return []

        fingerprints = [f.fingerprint for f in findings]
        result = await db.execute(select(VSFinding).where(VSFinding.fingerprint.in_(fingerprints)))
        existing = {row.fingerprint: row for row in result.scalars().all()}

        new_findings: list[VSFinding] = []
        now = datetime.now(timezone.utc)

        for finding in findings:
            prev = existing.get(finding.fingerprint)
            if prev:
                prev.occurrence_count = int(prev.occurrence_count or 1) + 1
                prev.last_seen = now
            else:
                new_findings.append(finding)

        return new_findings
