"""
Impersonation Monitoring Scanner — orchestrates M1–M8 sub-scanners.
Each sub-scanner is a stub: it logs a warning about missing integration
and returns an empty list. Real implementations can be dropped in.
"""
import json
import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)


def _utcnow():
    return datetime.now(timezone.utc)


def _make_fingerprint(module: str, platform: str, identifier: str) -> str:
    raw = f"{module}:{platform}:{identifier}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


async def run_scan_for_rule(rule_id: int) -> dict:
    """
    Main entry point: run all enabled modules for a given ImpersonationRule.
    Returns a summary dict with counts per module.
    """
    from app.database import AsyncSessionLocal
    from app.models import ImpersonationFinding, ImpersonationRule

    summary = {m: {"scanned": 0, "new_findings": 0, "errors": 0}
               for m in ["m1", "m2", "m3", "m5", "m6", "m7", "m8"]}

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ImpersonationRule).where(ImpersonationRule.id == rule_id)
        )
        rule = result.scalar_one_or_none()
        if not rule:
            logger.warning("[IMP] Rule %s not found", rule_id)
            return summary

        rule_data = {
            "id": rule.id,
            "brand_name": rule.brand_name,
            "brand_name_uk": rule.brand_name_uk,
            "brand_name_ru": rule.brand_name_ru,
            "official_domains": json.loads(rule.official_domains or "[]"),
            "official_developer_ids": json.loads(rule.official_developer_ids or "[]"),
            "executive_names": json.loads(rule.executive_names or "[]"),
            "partner_domains": json.loads(rule.partner_domains or "[]"),
            "social_platforms": json.loads(rule.social_platforms or '["telegram","instagram","vk","facebook"]'),
            "min_impersonation_score": rule.min_impersonation_score,
        }

        all_findings = []

        if rule.m1_social_enabled:
            try:
                findings = await _scan_m1_social(rule_data)
                all_findings.extend(findings)
                summary["m1"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M1 scan error for rule %s: %s", rule_id, exc)
                summary["m1"]["errors"] += 1

        if rule.m2_apps_enabled:
            try:
                findings = await _scan_m2_apps(rule_data)
                all_findings.extend(findings)
                summary["m2"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M2 scan error for rule %s: %s", rule_id, exc)
                summary["m2"]["errors"] += 1

        if rule.m3_email_enabled:
            try:
                findings = await _scan_m3_email(rule_data)
                all_findings.extend(findings)
                summary["m3"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M3 scan error for rule %s: %s", rule_id, exc)
                summary["m3"]["errors"] += 1

        if rule.m5_exec_enabled:
            try:
                findings = await _scan_m5_executive(rule_data)
                all_findings.extend(findings)
                summary["m5"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M5 scan error for rule %s: %s", rule_id, exc)
                summary["m5"]["errors"] += 1

        if rule.m6_ads_enabled:
            try:
                findings = await _scan_m6_ads(rule_data)
                all_findings.extend(findings)
                summary["m6"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M6 scan error for rule %s: %s", rule_id, exc)
                summary["m6"]["errors"] += 1

        if rule.m7_vip_enabled:
            try:
                findings = await _scan_m7_vip(rule_data)
                all_findings.extend(findings)
                summary["m7"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M7 scan error for rule %s: %s", rule_id, exc)
                summary["m7"]["errors"] += 1

        if rule.m8_domain_enabled:
            try:
                findings = await _scan_m8_domains(rule_data)
                all_findings.extend(findings)
                summary["m8"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP] M8 scan error for rule %s: %s", rule_id, exc)
                summary["m8"]["errors"] += 1

        for finding_payload in all_findings:
            fingerprint = _make_fingerprint(
                finding_payload["module"],
                finding_payload["platform"],
                finding_payload["target_identifier"],
            )
            existing = await db.execute(
                select(ImpersonationFinding).where(ImpersonationFinding.fingerprint == fingerprint)
            )
            existing_row = existing.scalar_one_or_none()
            if existing_row:
                existing_row.last_seen = _utcnow()
                existing_row.threat_score = finding_payload.get("threat_score", existing_row.threat_score)
                continue

            new_finding = ImpersonationFinding(
                rule_id=rule_id,
                module=finding_payload["module"],
                platform=finding_payload["platform"],
                finding_type=finding_payload.get("finding_type", "unknown"),
                target_url=finding_payload.get("target_url", ""),
                target_identifier=finding_payload["target_identifier"],
                display_name=finding_payload.get("display_name", ""),
                description=finding_payload.get("description", ""),
                subscriber_count=finding_payload.get("subscriber_count"),
                threat_score=finding_payload.get("threat_score", 0),
                signals_json=json.dumps(finding_payload.get("signals", [])),
                evidence_json=json.dumps(finding_payload.get("evidence", {})),
                fingerprint=fingerprint,
            )
            try:
                async with db.begin_nested():
                    db.add(new_finding)
                    await db.flush()
                summary[finding_payload["module"]]["new_findings"] += 1
            except IntegrityError:
                logger.info("[IMP] Duplicate finding skipped for fingerprint %s", fingerprint)

        rule.last_scan_at = _utcnow()
        await db.commit()

    return summary


async def _scan_m1_social(rule: dict) -> list:
    """M1: Fake Social Media Account Detection — stub."""
    logger.info(
        "[IMP M1] Social scan stub for '%s'. Configure Telethon/Apify integrations to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m2_apps(rule: dict) -> list:
    """M2: Malicious & Fake App Detection — stub."""
    logger.info(
        "[IMP M2] App store scan stub for '%s'. Install google-play-scraper and configure Apify to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m3_email(rule: dict) -> list:
    """M3: Corporate Email & CEO Fraud Protection — stub."""
    logger.info(
        "[IMP M3] Email/DMARC scan stub for '%s'. Install checkdmarc to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m5_executive(rule: dict) -> list:
    """M5: Executive Protection (HIBP / paste sites) — stub."""
    logger.info(
        "[IMP M5] Executive protection scan stub for '%s'. Configure HIBP API integration to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m6_ads(rule: dict) -> list:
    """M6: Ad Fraud Detection — stub."""
    logger.info(
        "[IMP M6] Ad fraud scan stub for '%s'. Configure Google Ads Transparency integration to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m7_vip(rule: dict) -> list:
    """M7: VIP Client & Partner Phishing Protection — stub."""
    logger.info("[IMP M7] VIP partner phishing scan stub for '%s'.", rule["brand_name"])
    return []


async def _scan_m8_domains(rule: dict) -> list:
    """M8: Preventive Domain Takedown (NRD feed) — stub."""
    logger.info(
        "[IMP M8] Domain takedown scan stub for '%s'. NRD feed integration required for real detection.",
        rule["brand_name"],
    )
    return []
