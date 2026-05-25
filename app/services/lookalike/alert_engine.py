"""
Alert engine — Look-alike Domains Phase 2.

async dispatch_lookalike_alerts(rule_id, newly_registered, db_session,
                                alert_threshold=50)

Queries the rule + brand from DB, checks each domain above the threshold for
duplicate suppression, then sends Email / Telegram / Slack notifications and
creates a BrandAlert row for audit.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Sequence

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import BrandAlert, Brand, LookalikeDomain, LookalikeRule
from app.services.notifications import send_email, send_telegram
from app.config import settings

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _build_evidence_text(rule: LookalikeRule, domain: LookalikeDomain) -> str:
    signals = json.loads(domain.signals_fired or "[]")
    lines = [
        f"Look-alike domain detected: {domain.fqdn}",
        f"Protected domain: {rule.protected_domain}",
        f"Threat score: {domain.threat_score} / 100  (severity {domain.severity})",
        f"Status: {domain.status}",
        f"IP: {domain.ip or 'N/A'}",
        f"Country: {domain.country_code or 'N/A'}",
        f"Registrar: {domain.registrar or 'N/A'}",
        f"Domain age (days): {domain.domain_age_days if domain.domain_age_days is not None else 'N/A'}",
        f"Signals fired: {', '.join(signals) if signals else 'none'}",
        f"First seen: {domain.first_seen_at.isoformat() if domain.first_seen_at else 'N/A'}",
    ]
    return "\n".join(lines)


async def dispatch_lookalike_alerts(
    rule_id: int,
    newly_registered: Sequence[LookalikeDomain],
    db_session: AsyncSession,
    alert_threshold: int = 50,
) -> dict:
    """
    Dispatch alerts for look-alike domains that exceed *alert_threshold*.

    Parameters
    ----------
    rule_id:
        ID of the LookalikeRule to process.
    newly_registered:
        Sequence of LookalikeDomain ORM objects from the most recent scan.
    db_session:
        Active async DB session.
    alert_threshold:
        Minimum threat_score to trigger an alert (default 50).

    Returns
    -------
    dict with keys ``sent`` and ``failed``.
    """
    sent = 0
    failed = 0

    # Load rule + brand
    rule_res = await db_session.execute(
        select(LookalikeRule).where(LookalikeRule.id == rule_id)
    )
    rule = rule_res.scalar_one_or_none()
    if not rule:
        logger.warning("[alert_engine] Rule %d not found", rule_id)
        return {"sent": 0, "failed": 0}

    brand_res = await db_session.execute(
        select(Brand).where(Brand.id == rule.brand_id)
    )
    brand = brand_res.scalar_one_or_none()
    if not brand:
        logger.warning("[alert_engine] Brand %d not found for rule %d", rule.brand_id, rule_id)
        return {"sent": 0, "failed": 0}

    # Read alert channels from Brand with graceful fallback (Phase 2 columns
    # may not exist on older DB schemas)
    alert_email: str = getattr(brand, "alert_email", "") or ""
    alert_telegram: str = getattr(brand, "alert_telegram", "") or ""
    slack_webhook: str = settings.slack_webhook_url or ""

    if not alert_email and not alert_telegram and not slack_webhook:
        logger.debug("[alert_engine] No alert channels configured for brand %d", brand.id)
        return {"sent": 0, "failed": 0}

    for domain in newly_registered:
        score = domain.threat_score or 0
        if score < alert_threshold:
            continue

        # Duplicate suppression — skip if a non-dismissed BrandAlert already exists
        existing_res = await db_session.execute(
            select(BrandAlert).where(
                BrandAlert.brand_id == brand.id,
                BrandAlert.similar_domain == domain.fqdn,
                BrandAlert.status != "dismissed",
            )
        )
        if existing_res.scalar_one_or_none():
            logger.debug("[alert_engine] Skipping duplicate alert for %s", domain.fqdn)
            continue

        evidence = _build_evidence_text(rule, domain)
        subject = f"[Zircon] Look-alike domain alert: {domain.fqdn}"

        ok = True

        # Email
        if alert_email:
            try:
                result = await send_email(alert_email, subject, evidence)
                if not result:
                    ok = False
            except Exception as exc:
                logger.warning("[alert_engine] Email error for %s: %s", domain.fqdn, exc)
                ok = False

        # Telegram
        if alert_telegram:
            try:
                msg = f"<b>{subject}</b>\n<pre>{evidence}</pre>"
                result = await send_telegram(alert_telegram, msg)
                if not result:
                    ok = False
            except Exception as exc:
                logger.warning("[alert_engine] Telegram error for %s: %s", domain.fqdn, exc)
                ok = False

        # Slack
        if slack_webhook:
            try:
                payload = {
                    "text": subject,
                    "blocks": [
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*{subject}*\n```{evidence}```"},
                        }
                    ],
                }
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(slack_webhook, json=payload)
                    if resp.status_code != 200:
                        ok = False
            except Exception as exc:
                logger.warning("[alert_engine] Slack error for %s: %s", domain.fqdn, exc)
                ok = False

        # Persist BrandAlert row
        try:
            alert_row = BrandAlert(
                brand_id=brand.id,
                similar_domain=domain.fqdn,
                similarity_score=domain.similarity_score or 0.0,
                source="lookalike_scan",
                details_json=json.dumps({
                    "rule_id": rule_id,
                    "domain_id": domain.id,
                    "threat_score": score,
                    "signals": json.loads(domain.signals_fired or "[]"),
                }),
                status="new",
                ip=domain.ip,
                alive=domain.has_a_record,
                checked_at=_utcnow(),
            )
            db_session.add(alert_row)
            await db_session.commit()
        except Exception as exc:
            logger.warning("[alert_engine] Failed to persist BrandAlert for %s: %s", domain.fqdn, exc)
            ok = False

        if ok:
            sent += 1
        else:
            failed += 1

    return {"sent": sent, "failed": failed}
