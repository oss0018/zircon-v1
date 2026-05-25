"""
Infrastructure Orchestrator — loads API keys from the Integration table and
runs enabled modules in parallel.
"""
import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import InfraFinding, InfraInvestigation, Integration
from app.services.crypto import decrypt

logger = logging.getLogger(__name__)

_MODULE_CLASSES = {
    "dns": "app.services.infrastructure_intelligence.dns_intelligence.DNSIntelligenceModule",
    "network": "app.services.infrastructure_intelligence.network_intelligence.NetworkIntelligenceModule",
    "cert": "app.services.infrastructure_intelligence.cert_intelligence.CertIntelligenceModule",
    "cloud": "app.services.infrastructure_intelligence.cloud_osint.CloudOSINTModule",
    "bgp_asn": "app.services.infrastructure_intelligence.bgp_asn.BGPASNModule",
}

_INFRA_SERVICE_TYPES = {
    "shodan", "censys", "securitytrails", "virustotal", "alienvault", "whoisxml", "leakix",
    "fofa", "zoomeye", "criminalip", "grayhatwarfare",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _import_class(dotted: str):
    module_path, class_name = dotted.rsplit(".", 1)
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


class InfraOrchestrator:
    async def _load_keys(self, db: AsyncSession) -> dict[str, str]:
        result = await db.execute(
            select(Integration).where(
                Integration.service_type.in_(_INFRA_SERVICE_TYPES),
                Integration.is_active.is_(True),
            )
        )
        integrations = result.scalars().all()
        keys: dict[str, str] = {}
        for integration in integrations:
            if integration.api_key_encrypted:
                try:
                    key = decrypt(integration.api_key_encrypted)
                    if key:
                        keys[integration.service_type] = key
                except Exception as exc:
                    logger.warning("Failed to decrypt key for %s: %s", integration.service_type, exc)
        return keys

    async def run_investigation(
        self,
        investigation_id: int,
        target: str,
        target_type: str,
        modules: list[str],
        db: AsyncSession,
    ) -> dict:
        try:
            # Mark running
            result = await db.execute(
                select(InfraInvestigation).where(InfraInvestigation.id == investigation_id)
            )
            investigation = result.scalar_one_or_none()
            if investigation is None:
                raise ValueError(f"Investigation {investigation_id} not found")

            investigation.status = "running"
            investigation.started_at = _utcnow()
            await db.commit()

            # Load integration keys
            keys = await self._load_keys(db)

            # Instantiate and run enabled modules in parallel
            tasks = []
            task_names = []
            # tech_stack depends on previously collected findings and runs post-gather.
            run_modules = [m for m in modules if m != "tech_stack"]
            if target_type == "asn" and "bgp_asn" not in run_modules:
                run_modules.append("bgp_asn")

            for module_name in run_modules:
                cls_path = _MODULE_CLASSES.get(module_name)
                if not cls_path:
                    continue
                cls = _import_class(cls_path)
                instance = cls(keys)
                tasks.append(instance.run(target, target_type))
                task_names.append(module_name)

            all_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Flatten findings and persist
            all_findings: list[dict] = []
            for module_name, module_result in zip(task_names, all_results):
                if isinstance(module_result, Exception):
                    logger.error("Module %s failed: %s", module_name, module_result)
                    continue
                all_findings.extend(module_result)

            if "tech_stack" in modules:
                try:
                    tech_cls = _import_class(
                        "app.services.infrastructure_intelligence.tech_stack.TechStackModule"
                    )
                    tech_instance = tech_cls(keys)
                    tech_findings = await tech_instance.run(
                        target,
                        target_type,
                        existing_findings=all_findings,
                    )
                    all_findings.extend(tech_findings)
                except Exception as exc:
                    logger.error("Module tech_stack failed: %s", exc)

            for finding in all_findings:
                data_json = finding.get("data_json", {})
                if not isinstance(data_json, str):
                    data_json = json.dumps(data_json)
                db_finding = InfraFinding(
                    investigation_id=investigation_id,
                    module=finding.get("module", ""),
                    finding_type=finding.get("finding_type", ""),
                    entity=str(finding.get("entity", ""))[:512],
                    severity=int(finding.get("severity", 1)),
                    source=str(finding.get("source", ""))[:100],
                    data_json=data_json,
                )
                db.add(db_finding)

            await db.flush()

            # Build summary
            from collections import Counter
            severity_counts: Counter = Counter()
            module_counts: Counter = Counter()
            for f in all_findings:
                module_counts[f.get("module", "unknown")] += 1
                sev = int(f.get("severity", 1))
                severity_counts[sev] += 1

            summary = dict(module_counts)
            summary["total"] = len(all_findings)
            summary["critical"] = severity_counts.get(5, 0)
            summary["high"] = severity_counts.get(4, 0)

            # Mark completed
            investigation.status = "completed"
            investigation.completed_at = _utcnow()
            investigation.summary_json = json.dumps(summary)
            await db.commit()

            return summary

        except Exception as exc:
            logger.exception("Investigation %d failed: %s", investigation_id, exc)
            try:
                result = await db.execute(
                    select(InfraInvestigation).where(InfraInvestigation.id == investigation_id)
                )
                investigation = result.scalar_one_or_none()
                if investigation:
                    investigation.status = "failed"
                    investigation.error_message = str(exc)[:1000]
                    await db.commit()
            except Exception as inner:
                logger.error("Failed to mark investigation %d as failed: %s", investigation_id, inner)
            raise
