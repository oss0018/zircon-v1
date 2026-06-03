"""
Impersonation Monitoring Scanner — orchestrates M1–M8 sub-scanners.
Each sub-scanner is a stub or a Phase-1 implementation; modules without an
integration log an info message and return an empty list.
"""
import asyncio
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
                logger.error("[IMP M1] Scan error for rule %s: %s", rule_id, exc)
                summary["m1"]["errors"] += 1

        if rule.m2_apps_enabled:
            try:
                findings = await _scan_m2_apps(rule_data)
                all_findings.extend(findings)
                summary["m2"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M2] Scan error for rule %s: %s", rule_id, exc)
                summary["m2"]["errors"] += 1

        if rule.m3_email_enabled:
            try:
                findings = await _scan_m3_email(rule_data)
                all_findings.extend(findings)
                summary["m3"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M3] Scan error for rule %s: %s", rule_id, exc)
                summary["m3"]["errors"] += 1

        if rule.m5_exec_enabled:
            try:
                findings = await _scan_m5_executive(rule_data)
                all_findings.extend(findings)
                summary["m5"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M5] Scan error for rule %s: %s", rule_id, exc)
                summary["m5"]["errors"] += 1

        if rule.m6_ads_enabled:
            try:
                findings = await _scan_m6_ads(rule_data)
                all_findings.extend(findings)
                summary["m6"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M6] Scan error for rule %s: %s", rule_id, exc)
                summary["m6"]["errors"] += 1

        if rule.m7_vip_enabled:
            try:
                findings = await _scan_m7_vip(rule_data)
                all_findings.extend(findings)
                summary["m7"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M7] Scan error for rule %s: %s", rule_id, exc)
                summary["m7"]["errors"] += 1

        if rule.m8_domain_enabled:
            try:
                findings = await _scan_m8_domains(rule_data)
                all_findings.extend(findings)
                summary["m8"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M8] Scan error for rule %s: %s", rule_id, exc)
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
    """M3: Corporate Email & CEO Fraud Protection — DMARC/SPF posture check.

    For every official domain on the rule, run an SPF + DMARC DNS lookup.
    Emit a finding when DMARC is missing, set to ``p=none``, or SPF is missing.
    Requires the ``checkdmarc`` package; if unavailable the scan is skipped.
    """
    domains = [d for d in (rule.get("official_domains") or []) if d]
    if not domains:
        return []

    try:
        import checkdmarc  # type: ignore
    except ImportError:
        logger.info(
            "[IMP M3] checkdmarc is not installed; M3 email scan skipped for '%s'.",
            rule["brand_name"],
        )
        return []

    findings: list[dict] = []
    for domain in domains:
        try:
            result = await asyncio.to_thread(
                checkdmarc.check_domains, [domain], skip_tls=True
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("[IMP M3] checkdmarc failed for %s: %s", domain, exc)
            continue

        if isinstance(result, list):
            entry = result[0] if result else {}
        elif isinstance(result, dict):
            entry = result
        else:
            entry = {}

        dmarc_info = entry.get("dmarc") or {}
        spf_info = entry.get("spf") or {}
        dmarc_record = dmarc_info.get("record") if isinstance(dmarc_info, dict) else None
        spf_record = spf_info.get("record") if isinstance(spf_info, dict) else None
        dmarc_tags = (
            (dmarc_info.get("tags") or {}) if isinstance(dmarc_info, dict) else {}
        )
        policy = ""
        if isinstance(dmarc_tags, dict):
            policy_tag = dmarc_tags.get("p")
            if isinstance(policy_tag, dict):
                policy = str(policy_tag.get("value") or "").lower()
            elif isinstance(policy_tag, str):
                policy = policy_tag.lower()

        if not dmarc_record:
            findings.append(
                {
                    "module": "m3",
                    "platform": "email",
                    "finding_type": "missing_dmarc",
                    "target_url": f"https://{domain}",
                    "target_identifier": domain,
                    "display_name": domain,
                    "description": (
                        f"Domain '{domain}' has no DMARC record. Spoofing protection is absent; "
                        "attackers can send email impersonating this domain."
                    ),
                    "threat_score": 70,
                    "signals": ["dmarc_missing"],
                    "evidence": {"dmarc": dmarc_info, "spf": spf_info},
                }
            )
            continue

        if policy in ("none", ""):
            findings.append(
                {
                    "module": "m3",
                    "platform": "email",
                    "finding_type": "weak_dmarc",
                    "target_url": f"https://{domain}",
                    "target_identifier": domain,
                    "display_name": domain,
                    "description": (
                        f"Domain '{domain}' publishes DMARC with p={policy or 'unset'}; "
                        "messages failing DMARC are not quarantined or rejected."
                    ),
                    "threat_score": 40,
                    "signals": ["dmarc_policy_none"],
                    "evidence": {"dmarc": dmarc_info, "spf": spf_info},
                }
            )

        if not spf_record:
            findings.append(
                {
                    "module": "m3",
                    "platform": "email",
                    "finding_type": "missing_spf",
                    "target_url": f"https://{domain}",
                    "target_identifier": f"spf:{domain}",
                    "display_name": domain,
                    "description": (
                        f"Domain '{domain}' has no SPF record. Receivers cannot verify which "
                        "hosts are authorised to send email on its behalf."
                    ),
                    "threat_score": 50,
                    "signals": ["spf_missing"],
                    "evidence": {"spf": spf_info},
                }
            )

    return findings


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
    """M8: Preventive Domain Takedown — fuzzy-match newly registered domains.

    Pulls the daily NRD feed via the existing ``app.services.lookalike.nrd_feed``
    and emits a finding for every domain whose token similarity to the brand
    name is above ``rule['min_impersonation_score']`` (capped at 95 to avoid
    duplicating exact official domains, which are filtered out explicitly).
    """
    brand = (rule.get("brand_name") or "").strip().lower()
    if not brand:
        return []

    official = {
        str(d).strip().lower()
        for d in (rule.get("official_domains") or [])
        if str(d).strip()
    }

    try:
        from app.services.lookalike.nrd_feed import fetch_nrd_domains
    except Exception as exc:  # noqa: BLE001
        logger.warning("[IMP M8] Could not import NRD feed module: %s", exc)
        return []

    try:
        from rapidfuzz import fuzz
    except ImportError:
        logger.info("[IMP M8] rapidfuzz not installed; M8 domain scan skipped.")
        return []

    try:
        domains = await fetch_nrd_domains()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[IMP M8] fetch_nrd_domains failed: %s", exc)
        return []

    threshold = max(int(rule.get("min_impersonation_score") or 40), 1)
    findings: list[dict] = []

    for fqdn in domains:
        if not fqdn or fqdn in official:
            continue
        # Compare against the SLD only (drop the TLD); use ratio + token_set_ratio
        # against a hyphen-split form so brand-as-token is detected without
        # over-matching short brand names.
        sld = fqdn.split(".")[0] if "." in fqdn else fqdn
        sld_tokens = sld.replace("-", " ")
        score = max(
            fuzz.ratio(brand, sld),
            fuzz.token_set_ratio(brand, sld_tokens),
        )
        if score < threshold:
            continue
        findings.append(
            {
                "module": "m8",
                "platform": "nrd",
                "finding_type": "suspicious_domain",
                "target_url": f"http://{fqdn}",
                "target_identifier": fqdn,
                "display_name": fqdn,
                "description": (
                    f"Newly-registered domain '{fqdn}' resembles brand '{rule['brand_name']}' "
                    f"(similarity {int(score)})."
                ),
                "threat_score": min(int(score), 95),
                "signals": ["nrd_similarity", f"score:{int(score)}"],
                "evidence": {"feed": "whoisds", "similarity": int(score)},
            }
        )

    return findings
