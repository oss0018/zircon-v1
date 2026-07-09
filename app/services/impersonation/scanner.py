"""
Impersonation Monitoring Scanner — orchestrates M1–M8 sub-scanners.
Each sub-scanner is a stub or a Phase-1 implementation; modules without an
integration log an info message and return an empty list.
"""
import asyncio
import json
import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)

# ── Scanner constants ─────────────────────────────────────────────────────────
# Maximum number of official domains used to derive candidate email addresses
# for executive name entries that aren't already in email format.
_MAX_DOMAINS_FOR_EMAIL_LASTNAME = 3   # firstname.lastname@<domain>
_MAX_DOMAINS_FOR_EMAIL_FIRSTNAME = 2  # firstname@<domain>

# Minimum length for a Telethon StringSession to be considered valid.
_MIN_TELEGRAM_SESSION_LENGTH = 20

# Maximum number of executive names converted to search terms per platform scan.
_MAX_EXEC_SEARCH_TERMS = 2

# Maximum number of official domains searched per dark-web scan. IntelX API
# plans are metered per request, so this is kept small by default.
_MAX_DARKWEB_DOMAIN_TERMS = 3


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
    from app.services.impersonation.alert_service import dispatch_for_finding

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

            # Phase 2 extended social platforms
            for _p2_stub in (_scan_m1_tiktok, _scan_m1_linkedin, _scan_m1_youtube):
                try:
                    p2_findings = await _p2_stub(rule_data)
                    all_findings.extend(p2_findings)
                    summary["m1"]["scanned"] += len(p2_findings)
                except Exception as exc:  # noqa: BLE001
                    logger.error("[IMP M1] Phase-2 scan error for rule %s: %s", rule_id, exc)
                    summary["m1"]["errors"] += 1

        if rule.m2_apps_enabled:
            try:
                findings = await _scan_m2_apps(rule_data)
                all_findings.extend(findings)
                summary["m2"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M2] Scan error for rule %s: %s", rule_id, exc)
                summary["m2"]["errors"] += 1

            # Phase 2: Apple App Store
            try:
                p2_findings = await _scan_m2_appstore(rule_data)
                all_findings.extend(p2_findings)
                summary["m2"]["scanned"] += len(p2_findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M2] Phase-2 appstore scan error for rule %s: %s", rule_id, exc)
                summary["m2"]["errors"] += 1

        if rule.m3_email_enabled:
            try:
                findings = await _scan_m3_email(rule_data)
                all_findings.extend(findings)
                summary["m3"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M3] Scan error for rule %s: %s", rule_id, exc)
                summary["m3"]["errors"] += 1

            # Phase 2: Honeypot + Inbound headers
            for _p2_stub in (_scan_m3_honeypot, _scan_m3_inbound_headers):
                try:
                    p2_findings = await _p2_stub(rule_data)
                    all_findings.extend(p2_findings)
                    summary["m3"]["scanned"] += len(p2_findings)
                except Exception as exc:  # noqa: BLE001
                    logger.error("[IMP M3] Phase-2 scan error for rule %s: %s", rule_id, exc)
                    summary["m3"]["errors"] += 1

        if rule.m5_exec_enabled:
            try:
                findings = await _scan_m5_executive(rule_data)
                all_findings.extend(findings)
                summary["m5"]["scanned"] = len(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M5] Scan error for rule %s: %s", rule_id, exc)
                summary["m5"]["errors"] += 1

            # Phase 2: Dark web monitoring
            try:
                p2_findings = await _scan_m5_darkweb(rule_data)
                all_findings.extend(p2_findings)
                summary["m5"]["scanned"] += len(p2_findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("[IMP M5] Phase-2 dark web scan error for rule %s: %s", rule_id, exc)
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

        findings_for_alert_evaluation: set[int] = set()
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
                findings_for_alert_evaluation.add(existing_row.id)
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
                    findings_for_alert_evaluation.add(new_finding.id)
                summary[finding_payload["module"]]["new_findings"] += 1
            except IntegrityError:
                logger.info("[IMP] Duplicate finding skipped for fingerprint %s", fingerprint)

        rule.last_scan_at = _utcnow()
        await db.commit()

        finding_rows = []
        if findings_for_alert_evaluation:
            finding_rows = (
                await db.execute(
                    select(ImpersonationFinding).where(
                        ImpersonationFinding.id.in_(findings_for_alert_evaluation)
                    )
                )
            ).scalars().all()

        for finding_row in finding_rows:
            dispatch_result = await dispatch_for_finding(db, finding_row)
            if dispatch_result.get("error"):
                logger.warning(
                    "[IMP] Alert dispatch failed for finding %s: %s",
                    finding_row.id,
                    dispatch_result.get("error"),
                )

    return summary


async def _scan_m1_social(rule: dict) -> list:
    """M1: Fake Social Media Account Detection.

    Dispatches to platform-specific sub-scanners (Telegram, Instagram, VK,
    Facebook) based on ``rule["social_platforms"]``.
    """
    platforms = [str(p).lower() for p in (rule.get("social_platforms") or [])]
    findings: list[dict] = []

    if "telegram" in platforms:
        try:
            findings.extend(await _scan_m1_telegram(rule))
        except Exception as exc:  # noqa: BLE001
            logger.error("[IMP M1] Telegram sub-scan error: %s", exc)

    if "instagram" in platforms:
        try:
            findings.extend(await _scan_m1_instagram(rule))
        except Exception as exc:  # noqa: BLE001
            logger.error("[IMP M1] Instagram sub-scan error: %s", exc)

    if "vk" in platforms:
        try:
            findings.extend(await _scan_m1_vk(rule))
        except Exception as exc:  # noqa: BLE001
            logger.error("[IMP M1] VK sub-scan error: %s", exc)

    if "facebook" in platforms:
        try:
            findings.extend(await _scan_m1_facebook(rule))
        except Exception as exc:  # noqa: BLE001
            logger.error("[IMP M1] Facebook sub-scan error: %s", exc)

    return findings


async def _scan_m1_tiktok(rule: dict) -> list:
    """M1 Phase 2: TikTok Account Impersonation Detection — stub.

    Searches for fake accounts using keywords: brand name, brand+official,
    brand+support, executive names. Checks follower engagement patterns,
    account age, and bio for phishing keywords.

    Integration: TikTok API or Apify TikTok scraper.
    Required env vars: TIKTOK_API_KEY or APIFY_TOKEN
    """
    logger.info(
        "[IMP M1] TikTok scan stub for '%s'. Configure TikTok API/Apify integration to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m1_linkedin(rule: dict) -> list:
    """M1 Phase 2: LinkedIn Account Impersonation Detection — stub.

    Searches by company name and executive profiles. Flags accounts with brand
    name combined with high executive impersonation confidence.

    Integration: LinkedIn API (limited public access).
    Required env vars: LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET
    """
    logger.info(
        "[IMP M1] LinkedIn scan stub for '%s'. Configure LinkedIn API integration to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m1_youtube(rule: dict) -> list:
    """M1 Phase 2: YouTube Channel Impersonation Detection — stub.

    Searches by brand name in channel titles/descriptions. Checks for phishing
    links in channel homepage/about section.

    Integration: YouTube Data API v3.
    Required env vars: YOUTUBE_API_KEY
    """
    logger.info(
        "[IMP M1] YouTube scan stub for '%s'. Configure YouTube Data API integration to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m2_apps(rule: dict) -> list:
    """M2: Malicious & Fake App Detection — Google Play."""
    return await _scan_m2_google_play(rule)


async def _scan_m2_appstore(rule: dict) -> list:
    """M2 Phase 2: Apple App Store Impersonation Detection — stub.

    Monitors for fake brand apps on Apple App Store. Detects impersonation in
    app name, icon, and description.

    Integration: App Store Connect API or Apify App Store scraper.
    Required env vars: APPSTORE_KEY_ID, APPSTORE_ISSUER_ID, APPSTORE_PRIVATE_KEY
    or APIFY_TOKEN (for Apify App Store scraper actor)
    """
    logger.info(
        "[IMP M2] Apple App Store scan stub for '%s'. Configure App Store Connect API/Apify to enable real detection.",
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
    """M5: Executive Protection — query executive emails against HIBP breach database.

    Uses the existing ``HIBPClient`` at ``app.services.osint.hibp``.
    Requires ``HIBP_API_KEY`` environment variable.

    Each entry in ``rule["executive_names"]`` may be either:
    - A full email address (``ceo@brand.com``) — queried directly.
    - A display name (``Jane Doe``) — candidate emails are constructed as
      ``firstname.lastname@<official_domain>`` and queried.
    """
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        logger.info(
            "[IMP M5] HIBP_API_KEY not configured; M5 executive scan skipped for '%s'.",
            rule["brand_name"],
        )
        return []

    executive_names: list[str] = rule.get("executive_names") or []
    official_domains: list[str] = [
        d.strip() for d in (rule.get("official_domains") or []) if d.strip()
    ]

    if not executive_names:
        return []

    from app.services.osint.hibp import HIBPClient  # local import to avoid circular refs

    client = HIBPClient(api_key=api_key)
    findings: list[dict] = []

    for exec_entry in executive_names:
        exec_entry = str(exec_entry).strip()
        if not exec_entry:
            continue

        # Build list of candidate emails to check
        if "@" in exec_entry:
            emails_to_check = [exec_entry]
        else:
            # Derive email candidates from name + official domains
            parts = exec_entry.lower().split()
            if len(parts) >= 2:
                # Strip characters that are invalid in the local part of an email address
                _slug = re.sub(r"[^a-z0-9]", "", parts[0])
                first = _slug or parts[0][:1]
                _slug_last = re.sub(r"[^a-z0-9]", "", parts[-1])
                last = _slug_last or parts[-1][:1]
                emails_to_check = [
                    f"{first}.{last}@{d}" for d in official_domains[:_MAX_DOMAINS_FOR_EMAIL_LASTNAME]
                ] + [f"{first}@{d}" for d in official_domains[:_MAX_DOMAINS_FOR_EMAIL_FIRSTNAME]]
            else:
                continue

        for email in emails_to_check:
            try:
                result = await client.search(email, query_type="email")
            except Exception as exc:  # noqa: BLE001
                logger.warning("[IMP M5] HIBP query failed for %s: %s", email, exc)
                continue

            # HIBPClient returns {"error": ...} when key is missing
            if result.get("error"):
                logger.info("[IMP M5] HIBP returned error for %s: %s", email, result["error"])
                break

            # Breaches are either under "breaches" key or at root if list
            if isinstance(result, list):
                breaches = result
            else:
                breaches = result.get("breaches") or []

            if not breaches:
                continue

            has_passwords = any(
                "Passwords" in (b.get("DataClasses") or []) for b in breaches
            )
            threat_score = 90 if has_passwords else 75
            breach_names = [b.get("Name", "Unknown") for b in breaches[:5]]
            signals = [f"breach:{n}" for n in breach_names[:3]]
            if has_passwords:
                signals.append("has_passwords")

            findings.append(
                {
                    "module": "m5",
                    "platform": "breach_database",
                    "finding_type": "executive_credentials_leaked",
                    "target_url": f"https://haveibeenpwned.com/account/{email}",
                    "target_identifier": email,
                    "display_name": f"{exec_entry} <{email}>",
                    "description": (
                        f"Executive email '{email}' found in {len(breaches)} data breach(es): "
                        f"{', '.join(breach_names)}."
                        + (" Password hashes included." if has_passwords else "")
                    ),
                    "threat_score": threat_score,
                    "signals": signals,
                    "evidence": {"breaches": breaches[:10], "email": email},
                }
            )

    return findings


async def _scan_m5_darkweb(rule: dict) -> list:
    """M5 Phase 2: Dark Web / Paste Site Monitoring — Intelligence X search.

    Complements ``_scan_m5_executive`` (which checks HIBP's curated breach
    corpus) by searching Intelligence X, a dark-web/paste-site/leak search
    engine that crawls Tor-hidden services and clearnet paste sites itself —
    no local Tor client or SOCKS proxy is needed to use it. This can surface
    bulk credential dumps and paste-site leaks referencing the brand's
    domains or executives that HIBP's known-breach corpus doesn't (yet)
    include.

    Uses the existing ``IntelXClient`` at ``app.services.osint.intelx``.
    Requires ``INTELX_API_KEY`` — a paid Intelligence X API subscription
    (see https://intelx.io/product); IntelX's free web tier does not include
    API access. Search terms (official domains, executive names) are capped
    since IntelX API plans are metered per request.

    Required env vars: INTELX_API_KEY
    Output type: ``darkweb_credential_leak``
    """
    api_key = os.getenv("INTELX_API_KEY", "").strip()
    if not api_key:
        logger.info(
            "[IMP M5] INTELX_API_KEY not configured; dark web scan skipped for '%s'.",
            rule.get("brand_name"),
        )
        return []

    official_domains: list[str] = [
        d.strip() for d in (rule.get("official_domains") or []) if d.strip()
    ]
    executive_names: list[str] = [
        e.strip() for e in (rule.get("executive_names") or []) if e.strip()
    ]

    if not official_domains and not executive_names:
        return []

    from app.services.osint.intelx import IntelXClient  # local import to avoid circular refs

    client = IntelXClient(api_key=api_key)
    findings: list[dict] = []

    search_terms: list[tuple[str, str]] = [
        (domain, "domain") for domain in official_domains[:_MAX_DARKWEB_DOMAIN_TERMS]
    ] + [
        (name, "executive") for name in executive_names[:_MAX_EXEC_SEARCH_TERMS]
    ]

    for term, term_type in search_terms:
        try:
            result = await client.search(term, query_type=term_type)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[IMP M5] IntelX query failed for '%s': %s", term, exc)
            continue

        if result.get("error"):
            logger.info("[IMP M5] IntelX returned error for '%s': %s", term, result["error"])
            continue

        records = result.get("records") or []
        if not isinstance(records, list) or not records:
            continue

        record_names = [
            str(name)[:120]
            for rec in records[:5]
            if isinstance(rec, dict) and (name := rec.get("name"))
        ]
        record_types = [
            str(rec.get("type")) for rec in records[:5] if isinstance(rec, dict) and rec.get("type")
        ]
        total_records = result.get("total")
        record_count = total_records if isinstance(total_records, int) else len(records)
        record_list_suffix = f": {', '.join(record_names)}" if record_names else ""
        signals = [f"intelx_type:{t}" for t in dict.fromkeys(record_types)][:3] or [
            f"intelx_term_type:{term_type}"
        ]

        findings.append(
            {
                "module": "m5",
                "platform": "dark_web",
                "finding_type": "darkweb_credential_leak",
                "target_url": f"https://intelx.io/?s={quote(term)}",
                "target_identifier": term,
                "display_name": f"{term} ({term_type})",
                "description": (
                    f"Found {record_count} dark web / paste-site record(s) referencing "
                    f"'{term}'{record_list_suffix}."
                ),
                "threat_score": 70,
                "signals": signals,
                "evidence": {"records": records[:10], "term": term, "term_type": term_type},
            }
        )

    return findings


async def _scan_m6_ads(rule: dict) -> list:
    """M6: Ad Fraud Detection — stub."""
    logger.info(
        "[IMP M6] Ad fraud scan stub for '%s'. Configure Google Ads Transparency integration to enable real detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m7_vip(rule: dict) -> list:
    """M7: VIP Client & Partner Phishing Protection.

    Compares every domain in the daily NRD feed against the rule's
    ``official_domains`` and ``partner_domains`` using rapidfuzz similarity.
    Domains with a similarity ratio ≥ 70 are flagged as potential
    lookalike/typosquat targets aimed at the brand's VIP partners.

    No external credentials required — reuses the existing NRD feed and
    rapidfuzz similarity engine.
    """
    from app.services.impersonation.score_calculators import (
        best_domain_similarity,
        score_badge,
    )

    official = [d.strip() for d in (rule.get("official_domains") or []) if d.strip()]
    partners = [d.strip() for d in (rule.get("partner_domains") or []) if d.strip()]
    protected = official + partners

    if not protected:
        logger.info(
            "[IMP M7] No official_domains or partner_domains configured for '%s'; M7 scan skipped.",
            rule["brand_name"],
        )
        return []

    try:
        from app.services.lookalike.nrd_feed import fetch_nrd_domains
    except Exception as exc:  # noqa: BLE001
        logger.warning("[IMP M7] Could not import NRD feed module: %s", exc)
        return []

    try:
        nrd_domains = await fetch_nrd_domains()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[IMP M7] fetch_nrd_domains failed: %s", exc)
        return []

    protected_lower = {d.lower() for d in protected}
    threshold = 70.0  # similarity % to flag (as per spec)
    findings: list[dict] = []

    for fqdn in nrd_domains:
        if not fqdn:
            continue
        fqdn_lower = fqdn.lower()
        if fqdn_lower in protected_lower:
            continue

        score, ref_domain = best_domain_similarity(fqdn_lower, protected)
        if score < threshold:
            continue

        threat_score = min(int(score), 95)
        badge = score_badge(threat_score)

        findings.append(
            {
                "module": "m7",
                "platform": "domain_registry",
                "finding_type": "vip_phishing_domain",
                "target_url": f"http://{fqdn}",
                "target_identifier": fqdn,
                "display_name": fqdn,
                "description": (
                    f"{badge} Newly-registered domain '{fqdn}' closely resembles protected "
                    f"domain '{ref_domain}' (similarity {int(score)}%). "
                    f"May be used for VIP partner phishing."
                ),
                "threat_score": threat_score,
                "signals": [
                    "vip_domain_lookalike",
                    f"score:{int(score)}",
                    f"ref:{ref_domain}",
                ],
                "evidence": {
                    "similarity": int(score),
                    "reference_domain": ref_domain,
                    "brand": rule["brand_name"],
                    "feed": "whoisds",
                },
            }
        )

    return findings


# ── M1 Platform-specific scanners ────────────────────────────────────────────


async def _scan_m1_telegram(rule: dict) -> list:
    """M1: Telegram — search public channels for brand impersonation.

    Uses an existing Telethon session (``TELEGRAM_API_ID``, ``TELEGRAM_API_HASH``,
    ``TELEGRAM_SESSION_STRING``) to query public channels.  Scores candidates by
    name similarity, keyword overlap, subscriber count, and channel age.

    Required env vars: TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_SESSION_STRING
    Output type: ``fake_telegram_account``
    """
    try:
        from telethon import TelegramClient  # type: ignore
        from telethon.tl.functions.contacts import SearchRequest  # type: ignore
        from telethon.sessions import StringSession  # type: ignore
    except ImportError:
        logger.info("[IMP M1] telethon not installed; Telegram impersonation scan skipped.")
        return []

    api_id_raw = os.getenv("TELEGRAM_API_ID", "").strip()
    api_hash = os.getenv("TELEGRAM_API_HASH", "").strip()
    session_string = os.getenv("TELEGRAM_SESSION_STRING", "").strip()

    if not api_id_raw or not api_hash or len(session_string) < _MIN_TELEGRAM_SESSION_LENGTH:
        logger.info(
            "[IMP M1] Telegram credentials not configured; Telegram impersonation scan skipped for '%s'.",
            rule["brand_name"],
        )
        return []

    try:
        api_id = int(api_id_raw)
    except ValueError:
        logger.warning("[IMP M1] TELEGRAM_API_ID is not a valid integer; Telegram scan skipped.")
        return []

    brand = (rule.get("brand_name") or "").strip()
    if not brand:
        return []

    try:
        from rapidfuzz import fuzz as _fuzz  # type: ignore
    except ImportError:
        _fuzz = None

    search_terms = [brand, f"{brand}_official", f"{brand}_support"]
    for exec_name in (rule.get("executive_names") or [])[:_MAX_EXEC_SEARCH_TERMS]:
        first = (str(exec_name).split() or [""])[0]
        if first:
            search_terms.append(first)

    client = TelegramClient(StringSession(session_string), api_id, api_hash)
    findings: list[dict] = []
    seen_ids: set[int] = set()

    try:
        await client.start()
        for term in search_terms:
            try:
                result = await client(SearchRequest(q=term, limit=20))
                channels = list(getattr(result, "chats", []))
            except Exception as exc:  # noqa: BLE001
                logger.warning("[IMP M1] Telegram search failed for '%s': %s", term, exc)
                continue

            for channel in channels:
                channel_id = getattr(channel, "id", None)
                if channel_id in seen_ids:
                    continue
                seen_ids.add(channel_id)

                title = str(getattr(channel, "title", "") or "").strip()
                username = str(getattr(channel, "username", "") or "").strip()
                subscribers = int(getattr(channel, "participants_count", 0) or 0)
                date = getattr(channel, "date", None)
                is_verified = bool(getattr(channel, "verified", False))

                if not title or is_verified:
                    continue

                # Scoring (max 100 pts)
                score = 0
                brand_lower = brand.lower()
                title_lower = title.lower()

                # Name similarity — up to 40 pts
                if _fuzz:
                    name_sim = _fuzz.partial_ratio(brand_lower, title_lower)
                    score += min(int(name_sim * 0.4), 40)

                # Brand exact match in name — 20 pts
                if brand_lower in title_lower:
                    score += 20

                # Official/support/service keywords — 5 pts each
                for kw in ("official", "support", "help", "service", "verified"):
                    if kw in title_lower:
                        score += 5

                # Large subscriber count — 10 pts (increases credibility risk)
                if subscribers > 1000:
                    score += 10

                # Newly created channel — 10 pts
                if date is not None:
                    try:
                        if date.tzinfo is None:
                            date = date.replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - date).days
                        if age_days < 30:
                            score += 10
                    except Exception:  # noqa: BLE001
                        pass

                min_score = int(rule.get("min_impersonation_score") or 40)
                if score < min_score:
                    continue

                channel_url = (
                    f"https://t.me/{username}"
                    if username
                    else f"https://t.me/c/{channel_id}"
                )
                findings.append(
                    {
                        "module": "m1",
                        "platform": "telegram",
                        "finding_type": "fake_telegram_account",
                        "target_url": channel_url,
                        "target_identifier": username or str(channel_id),
                        "display_name": title,
                        "description": (
                            f"Telegram channel '{title}'"
                            + (f" (@{username})" if username else "")
                            + f" may be impersonating '{brand}' (score {score}). "
                            f"Subscribers: {subscribers}."
                        ),
                        "threat_score": min(score, 95),
                        "subscriber_count": subscribers,
                        "signals": ["telegram_impersonation", f"score:{score}"],
                        "evidence": {
                            "channel_id": channel_id,
                            "username": username,
                            "title": title,
                            "subscribers": subscribers,
                        },
                    }
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[IMP M1] Telegram client error: %s", exc)
    finally:
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001
            pass

    return findings


async def _scan_m1_instagram(rule: dict) -> list:
    """M1: Instagram — detect fake brand accounts via Apify actor.

    Calls the Apify Instagram Username Checker actor for a set of brand-derived
    username patterns.  Scores results by name similarity and keyword presence.

    Required env vars: APIFY_API_KEY
    Output type: ``fake_instagram_account``
    """
    apify_key = os.getenv("APIFY_API_KEY", "").strip()
    if not apify_key:
        logger.info(
            "[IMP M1] APIFY_API_KEY not configured; Instagram scan skipped for '%s'.",
            rule["brand_name"],
        )
        return []

    brand = (rule.get("brand_name") or "").strip()
    if not brand:
        return []

    brand_slug = re.sub(r"[^a-z0-9]", "", brand.lower())

    search_usernames = [
        brand_slug,
        f"{brand_slug}official",
        f"{brand_slug}_official",
        f"{brand_slug}.official",
        f"{brand_slug}_support",
    ]
    for exec_name in (rule.get("executive_names") or [])[:_MAX_EXEC_SEARCH_TERMS]:
        parts = str(exec_name).lower().split()
        if len(parts) >= 2:
            search_usernames.append(f"{parts[0]}_{parts[-1]}")

    try:
        from rapidfuzz import fuzz as _fuzz  # type: ignore
    except ImportError:
        _fuzz = None

    findings: list[dict] = []
    actor_url = (
        "https://api.apify.com/v2/acts/apify~instagram-scraper/run-sync-get-dataset-items"
    )

    for username in search_usernames:
        payload = {
            "usernames": [username],
            "resultsLimit": 1,
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    actor_url,
                    json=payload,
                    headers={"Authorization": "Bearer " + apify_key},
                )
                if resp.status_code not in (200, 201):
                    logger.debug(
                        "[IMP M1] Apify Instagram returned %s for '%s'",
                        resp.status_code,
                        username,
                    )
                    continue
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[IMP M1] Apify Instagram error for '%s': %s", username, exc)
            continue

        if not isinstance(data, list):
            data = [data] if data else []

        for account in data:
            if not isinstance(account, dict):
                continue
            account_username = str(account.get("username") or username)
            full_name = str(account.get("fullName") or account.get("full_name") or "")
            followers = int(account.get("followersCount") or account.get("followers_count") or 0)
            is_verified = bool(account.get("isVerified") or account.get("is_verified"))
            bio = str(account.get("biography") or account.get("bio") or "")

            if is_verified:
                continue

            # Scoring
            score = 0
            brand_lower = brand.lower()
            if _fuzz:
                name_sim = max(
                    _fuzz.partial_ratio(brand_lower, account_username.lower()),
                    _fuzz.partial_ratio(brand_lower, full_name.lower()) if full_name else 0,
                )
                score += min(int(name_sim * 0.5), 50)
            elif brand_lower in account_username.lower():
                score += 40

            # Official/support keywords — 10 pts each
            for kw in ("official", "support", "service", "help"):
                if kw in account_username.lower() or kw in full_name.lower():
                    score += 10

            # Phishing bio keywords — 5 pts each
            for kw in ("login", "verify", "click", "free", "giveaway"):
                if kw in bio.lower():
                    score += 5

            min_score = int(rule.get("min_impersonation_score") or 40)
            if score < min_score:
                continue

            findings.append(
                {
                    "module": "m1",
                    "platform": "instagram",
                    "finding_type": "fake_instagram_account",
                    "target_url": f"https://www.instagram.com/{account_username}/",
                    "target_identifier": account_username,
                    "display_name": full_name or account_username,
                    "description": (
                        f"Instagram account '@{account_username}' may be impersonating "
                        f"'{brand}' (score {score}). Followers: {followers}."
                    ),
                    "threat_score": min(score, 95),
                    "subscriber_count": followers,
                    "signals": ["instagram_impersonation", f"score:{score}"],
                    "evidence": account,
                }
            )

    return findings


async def _scan_m1_vk(rule: dict) -> list:
    """M1: VK (VKontakte) — detect fake brand communities via VK API.

    Calls ``groups.search`` with brand-derived queries and scores results by
    name similarity, keyword presence, verification status, and member count.

    Required env vars: VK_SERVICE_TOKEN
    Output type: ``fake_vk_account``
    """
    vk_token = os.getenv("VK_SERVICE_TOKEN", "").strip()
    if not vk_token:
        logger.info(
            "[IMP M1] VK_SERVICE_TOKEN not configured; VK scan skipped for '%s'.",
            rule["brand_name"],
        )
        return []

    brand = (rule.get("brand_name") or "").strip()
    if not brand:
        return []

    try:
        from rapidfuzz import fuzz as _fuzz  # type: ignore
    except ImportError:
        _fuzz = None

    findings: list[dict] = []
    seen_ids: set[int] = set()
    search_queries = [brand, f"{brand} official", f"{brand} support"]

    for query in search_queries:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://api.vk.com/method/groups.search",
                    params={
                        "q": query,
                        "type": "group,public",
                        "count": 10,
                        "fields": "members_count,verified,screen_name",
                        "access_token": vk_token,
                        "v": "5.131",
                    },
                )
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[IMP M1] VK API error for query '%s': %s", query, exc)
            continue

        groups = (data.get("response") or {}).get("items") or []

        for group in groups:
            group_id = group.get("id")
            if not group_id or group_id in seen_ids:
                continue
            seen_ids.add(group_id)

            group_name = str(group.get("name") or "")
            screen_name = str(group.get("screen_name") or "")
            members = int(group.get("members_count") or 0)
            is_verified = bool(group.get("verified"))

            if is_verified:
                continue

            # Scoring
            score = 0
            brand_lower = brand.lower()
            name_lower = group_name.lower()

            # Name similarity — up to 40 pts
            if _fuzz:
                name_sim = _fuzz.partial_ratio(brand_lower, name_lower)
                score += min(int(name_sim * 0.4), 40)

            # Brand exact match — 20 pts
            if brand_lower in name_lower:
                score += 20

            # Unverified brand-claiming community — 15 pts
            if not is_verified and brand_lower in name_lower:
                score += 15

            # Official/support keywords — 5 pts each
            for kw in ("official", "support", "help"):
                if kw in name_lower:
                    score += 5

            min_score = int(rule.get("min_impersonation_score") or 40)
            if score < min_score:
                continue

            group_url = (
                f"https://vk.com/{screen_name}"
                if screen_name
                else f"https://vk.com/club{group_id}"
            )
            findings.append(
                {
                    "module": "m1",
                    "platform": "vk",
                    "finding_type": "fake_vk_account",
                    "target_url": group_url,
                    "target_identifier": screen_name or str(group_id),
                    "display_name": group_name,
                    "description": (
                        f"VK community '{group_name}' ({group_url}) may be impersonating "
                        f"'{brand}' (score {score}). Members: {members}."
                    ),
                    "threat_score": min(score, 95),
                    "subscriber_count": members,
                    "signals": ["vk_impersonation", f"score:{score}"],
                    "evidence": group,
                }
            )

    return findings


async def _scan_m1_facebook(rule: dict) -> list:
    """M1: Facebook — detect fake brand Pages via a configurable Apify actor.

    Meta's Graph API no longer permits arbitrary keyword search of public
    Pages for third-party apps (that requires Meta's "Page Public Content
    Access" feature review), and unlike Instagram there is no single official
    Apify actor for Facebook Page search. Operators must point this scanner at
    an Apify actor of their choosing via ``FACEBOOK_APIFY_ACTOR`` (browse
    options at https://apify.com/store?search=facebook). The actor's input
    field name for the search keyword defaults to ``keyword`` and can be
    overridden with ``FACEBOOK_APIFY_SEARCH_FIELD`` for actors that expect a
    different field name.

    Required env vars: APIFY_API_KEY (shared with Instagram), FACEBOOK_APIFY_ACTOR
    Optional env vars: FACEBOOK_APIFY_SEARCH_FIELD (default: "keyword")
    Output type: ``fake_facebook_page``
    """
    apify_key = os.getenv("APIFY_API_KEY", "").strip()
    if not apify_key:
        logger.info(
            "[IMP M1] APIFY_API_KEY not configured; Facebook scan skipped for '%s'.",
            rule["brand_name"],
        )
        return []

    actor = os.getenv("FACEBOOK_APIFY_ACTOR", "").strip()
    if not actor:
        logger.info(
            "[IMP M1] FACEBOOK_APIFY_ACTOR not configured; Facebook scan skipped for '%s'. "
            "No single official Apify actor exists for Facebook Page search — set "
            "FACEBOOK_APIFY_ACTOR to an actor id from https://apify.com/store?search=facebook.",
            rule["brand_name"],
        )
        return []

    brand = (rule.get("brand_name") or "").strip()
    if not brand:
        return []

    search_field = os.getenv("FACEBOOK_APIFY_SEARCH_FIELD", "keyword").strip() or "keyword"

    try:
        from rapidfuzz import fuzz as _fuzz  # type: ignore
    except ImportError:
        _fuzz = None

    findings: list[dict] = []
    seen_ids: set[str] = set()
    search_queries = [brand, f"{brand} official", f"{brand} support"]
    for exec_name in (rule.get("executive_names") or [])[:_MAX_EXEC_SEARCH_TERMS]:
        parts = str(exec_name).split()
        if parts:
            search_queries.append(f"{brand} {parts[0]}")

    actor_url = f"https://api.apify.com/v2/acts/{actor}/run-sync-get-dataset-items"

    for query in search_queries:
        payload = {search_field: query, "maxItems": 10}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    actor_url,
                    json=payload,
                    headers={"Authorization": "Bearer " + apify_key},
                )
                if resp.status_code not in (200, 201):
                    logger.debug(
                        "[IMP M1] Apify Facebook returned %s for '%s'",
                        resp.status_code,
                        query,
                    )
                    continue
                data = resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning("[IMP M1] Apify Facebook error for '%s': %s", query, exc)
            continue

        if not isinstance(data, list):
            data = [data] if data else []

        for page in data:
            if not isinstance(page, dict):
                continue

            page_id = str(page.get("pageId") or page.get("id") or page.get("facebookId") or "")
            username = str(page.get("pageUsername") or page.get("username") or "")
            identifier = username or page_id
            if not identifier or identifier in seen_ids:
                continue
            seen_ids.add(identifier)

            page_name = str(page.get("pageName") or page.get("name") or page.get("title") or "")
            page_url = str(
                page.get("pageUrl")
                or page.get("url")
                or page.get("link")
                or f"https://www.facebook.com/{identifier}"
            )
            followers = int(
                page.get("followers")
                or page.get("likes")
                or page.get("fan_count")
                or page.get("followersCount")
                or 0
            )
            is_verified = bool(page.get("verified") or page.get("isVerified"))

            if not page_name or is_verified:
                continue

            # Scoring
            score = 0
            brand_lower = brand.lower()
            name_lower = page_name.lower()
            username_lower = username.lower()

            if _fuzz:
                name_sim = max(
                    _fuzz.partial_ratio(brand_lower, name_lower),
                    _fuzz.partial_ratio(brand_lower, username_lower) if username_lower else 0,
                )
                score += min(int(name_sim * 0.5), 50)
            elif brand_lower in name_lower or (username_lower and brand_lower in username_lower):
                score += 40

            # Official/support keywords — 10 pts each
            for kw in ("official", "support", "service", "help"):
                if kw in name_lower or kw in username_lower:
                    score += 10

            min_score = int(rule.get("min_impersonation_score") or 40)
            if score < min_score:
                continue

            findings.append(
                {
                    "module": "m1",
                    "platform": "facebook",
                    "finding_type": "fake_facebook_page",
                    "target_url": page_url,
                    "target_identifier": identifier,
                    "display_name": page_name,
                    "description": (
                        f"Facebook Page '{page_name}' ({page_url}) may be impersonating "
                        f"'{brand}' (score {score}). Followers: {followers}."
                    ),
                    "threat_score": min(score, 95),
                    "subscriber_count": followers,
                    "signals": ["facebook_impersonation", f"score:{score}"],
                    "evidence": page,
                }
            )

    return findings


# ── M2 Platform-specific scanners ────────────────────────────────────────────


async def _scan_m2_google_play(rule: dict) -> list:
    """M2: Google Play — detect fake brand apps via google-play-scraper.

    Searches the Play Store by brand name and flags apps with ≥75% name
    similarity that are **not** published by a known official developer ID.
    Checks for suspicious permissions (SMS, contacts, location).

    Required: ``pip install google-play-scraper``
    Output type: ``fake_mobile_app``
    """
    brand = (rule.get("brand_name") or "").strip()
    if not brand:
        return []

    try:
        from google_play_scraper import search as gplay_search  # type: ignore
    except ImportError:
        logger.info(
            "[IMP M2] google-play-scraper not installed; Google Play scan skipped for '%s'. "
            "Install with: pip install google-play-scraper",
            brand,
        )
        return []

    try:
        from rapidfuzz import fuzz as _fuzz  # type: ignore
    except ImportError:
        _fuzz = None

    official_ids = {
        str(i).strip().lower()
        for i in (rule.get("official_developer_ids") or [])
        if str(i).strip()
    }

    try:
        results = await asyncio.to_thread(
            gplay_search, brand, lang="en", country="us", n_hits=20
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("[IMP M2] Google Play search failed for '%s': %s", brand, exc)
        return []

    _SUSPICIOUS_PERMS = {
        "READ_CONTACTS",
        "READ_SMS",
        "ACCESS_FINE_LOCATION",
        "SEND_SMS",
        "CALL_PHONE",
        "READ_CALL_LOG",
    }

    findings: list[dict] = []
    brand_lower = brand.lower()

    for app in (results or []):
        app_id = str(app.get("appId") or "")
        app_name = str(app.get("title") or "")
        developer = str(app.get("developer") or "")
        developer_id = str(app.get("developerId") or "").lower()

        # Skip apps from official developers
        if developer_id and developer_id in official_ids:
            continue

        # Name similarity
        if _fuzz:
            name_sim = max(
                _fuzz.ratio(brand_lower, app_name.lower()),
                _fuzz.partial_ratio(brand_lower, app_name.lower()),
            )
        else:
            name_sim = 100.0 if brand_lower in app_name.lower() else 0.0

        if name_sim < 75:
            continue

        # Suspicious permissions
        permissions = set(app.get("permissions") or [])
        suspicious = permissions & _SUSPICIOUS_PERMS
        threat_score = min(int(name_sim) + (10 if suspicious else 0), 95)

        signals = [f"name_similarity:{int(name_sim)}"]
        if suspicious:
            signals.append(f"suspicious_permissions:{','.join(sorted(suspicious))}")

        findings.append(
            {
                "module": "m2",
                "platform": "google_play",
                "finding_type": "fake_mobile_app",
                "target_url": f"https://play.google.com/store/apps/details?id={app_id}",
                "target_identifier": app_id,
                "display_name": app_name,
                "description": (
                    f"Google Play app '{app_name}' (ID: {app_id}) matches brand '{brand}' "
                    f"(name similarity {int(name_sim)}%). Developer: {developer}."
                    + (
                        f" Suspicious permissions: {', '.join(sorted(suspicious))}."
                        if suspicious
                        else ""
                    )
                ),
                "threat_score": threat_score,
                "signals": signals,
                "evidence": {
                    "app_id": app_id,
                    "developer": developer,
                    "developer_id": developer_id,
                    "name_similarity": int(name_sim),
                    "installs": app.get("minInstalls"),
                    "rating": app.get("score"),
                    "suspicious_permissions": sorted(suspicious),
                },
            }
        )

    return findings


async def _scan_m3_honeypot(rule: dict) -> list:
    """M3 Phase 2: MX Honeypot for CEO Fraud Detection — stub.

    Sets up catch-all email addresses to detect incoming CEO fraud emails.
    Pattern: ceo-honeypot@{protected_domain}, finance-honeypot@{protected_domain}.
    Uses ML-based BEC detection on incoming messages.

    Integration: SMTP server access + Email security service.
    Required env vars: HONEYPOT_SMTP_HOST, HONEYPOT_SMTP_PORT, HONEYPOT_MAILBOXES
    """
    domains = [d for d in (rule.get("official_domains") or []) if d]
    if not domains:
        return []
    logger.info(
        "[IMP M3] MX honeypot scan stub for '%s'. Configure SMTP/honeypot integration to enable CEO fraud detection.",
        rule["brand_name"],
    )
    return []


async def _scan_m3_inbound_headers(rule: dict) -> list:
    """M3 Phase 2: Inbound Email Header Analysis — stub.

    Analyses received emails for spoofing patterns: SPF failures, DKIM failures,
    DMARC failures. Requires Exchange/Gmail integration for email header access.

    Integration: Microsoft Graph API or Google Workspace API.
    Required env vars: MSGRAPH_CLIENT_ID, MSGRAPH_TENANT_ID, MSGRAPH_CLIENT_SECRET
    or GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON
    """
    domains = [d for d in (rule.get("official_domains") or []) if d]
    if not domains:
        return []
    logger.info(
        "[IMP M3] Inbound header analysis stub for '%s'. Configure Microsoft Graph/Google Workspace API to enable real detection.",
        rule["brand_name"],
    )
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
