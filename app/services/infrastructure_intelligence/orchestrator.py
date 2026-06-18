"""
Infrastructure Orchestrator — loads API keys from the Integration table and
runs enabled modules in parallel.
"""
import asyncio
import ipaddress
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import InfraFinding, InfraInvestigation, Integration
from app.services.crypto import decrypt
from app.services.infrastructure_intelligence.bgp_asn import BGPASNModule
from app.services.infrastructure_intelligence.tech_stack import TechStackModule

logger = logging.getLogger(__name__)

_MODULE_CLASSES = {
    "dns": "app.services.infrastructure_intelligence.dns_intelligence.DNSIntelligenceModule",
    "network": "app.services.infrastructure_intelligence.network_intelligence.NetworkIntelligenceModule",
    "cert": "app.services.infrastructure_intelligence.cert_intelligence.CertIntelligenceModule",
    "cloud": "app.services.infrastructure_intelligence.cloud_osint.CloudOSINTModule",
}
_PARALLEL_MODULES = (*_MODULE_CLASSES.keys(), "bgp_asn")

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

            # Instantiate and run first-phase modules in parallel
            tasks = []
            task_names = []
            for module_name in _PARALLEL_MODULES:
                if module_name not in modules:
                    continue
                cls_path = _MODULE_CLASSES.get(module_name)
                if module_name == "bgp_asn":
                    instance = BGPASNModule(keys)
                else:
                    if not cls_path:
                        continue
                    cls = _import_class(cls_path)
                    instance = cls(keys)
                tasks.append(instance.run(target, target_type))
                task_names.append(module_name)

            all_results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []

            # Flatten findings and persist
            all_findings: list[dict] = []
            for module_name, module_result in zip(task_names, all_results):
                if isinstance(module_result, Exception):
                    logger.error("Module %s failed: %s", module_name, module_result)
                    continue
                all_findings.extend(module_result)

            if "tech_stack" in modules:
                tech_stack = TechStackModule()
                try:
                    tech_findings = await tech_stack.run(target, target_type, all_findings)
                    all_findings.extend(tech_findings)
                except Exception as exc:
                    logger.error("Module tech_stack failed: %s", exc)

            # Post-gather: run certificate analysis on specific discovered
            # network endpoints when cert module is requested. For domain
            # investigations the parallel cert module only queries CT logs, so
            # we still need TLS-handshake analysis against discovered services.
            if "cert" in modules:
                endpoints: set[tuple[str, int] | tuple[str, int, str]] = set()
                unique_ips: set[str] = set()

                for f in all_findings:
                    if f.get("module") != "network":
                        continue

                    data = f.get("data_json", {})
                    if isinstance(data, str):
                        try:
                            data = json.loads(data)
                        except Exception:
                            data = {}

                    ip = data.get("ip")
                    port = data.get("port")

                    if not ip or not port:
                        entity = str(f.get("entity", ""))
                        if ":" in entity:
                            ip, _, port_raw = entity.rpartition(":")
                            try:
                                port = int(port_raw)
                            except Exception:
                                port = None

                    try:
                        ipaddress.ip_address(str(ip))
                        if port:
                            if target_type == "domain":
                                endpoints.add((str(ip), int(port), target))
                            else:
                                endpoints.add((str(ip), int(port)))
                        else:
                            unique_ips.add(str(ip))
                    except ValueError:
                        pass

                if endpoints or unique_ips:
                    from app.services.infrastructure_intelligence.cert_intelligence import (
                        CertIntelligenceModule,
                    )
                    cert_module = CertIntelligenceModule(keys)
                    try:
                        cert_findings: list[dict] = []
                        if endpoints:
                            cert_findings.extend(
                                await cert_module.analyze_endpoints(list(endpoints)[:32])
                            )
                        elif unique_ips:
                            cert_findings.extend(
                                await cert_module.analyze_self_signed(list(unique_ips)[:32])
                            )
                        all_findings.extend(cert_findings)
                    except Exception as exc:
                        logger.error("Post-gather cert analysis failed: %s", exc)

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
            summary.setdefault("tech_stack", 0)
            summary.setdefault("bgp_asn", 0)
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
