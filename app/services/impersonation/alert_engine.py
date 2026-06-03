"""
Alert Engine — Impersonation Monitoring Phase 2 (TS-IMP-001 v2).

Dispatches real-time notifications when a new ImpersonationFinding matches
one or more AlertRule records.  Supports Slack, PagerDuty, Microsoft Teams,
and Telegram channels.  Called from the scanner orchestrator after new
findings are persisted.

Usage::

    from app.services.impersonation.alert_engine import dispatch_alerts
    await dispatch_alerts(finding_id=42)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _finding_to_text(finding: Any) -> str:
    """Build a human-readable alert body from an ImpersonationFinding ORM row."""
    lines = [
        f"🚨 Impersonation Finding — {finding.module.upper()} / {finding.platform}",
        f"Type: {finding.finding_type}",
        f"Target: {finding.display_name or finding.target_identifier}",
        f"URL: {finding.target_url or '—'}",
        f"Threat score: {finding.threat_score} / 100",
        f"Status: {finding.status}",
        f"Detected: {finding.first_seen.isoformat() if finding.first_seen else '—'}",
    ]
    return "\n".join(lines)


async def _send_slack(webhook_url: str, text: str) -> bool:
    """POST a plain-text message to a Slack Incoming Webhook."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json={"text": text})
            resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[AlertEngine] Slack dispatch failed: %s", exc)
        return False


async def _send_pagerduty(integration_key: str, title: str, body: str) -> bool:
    """Trigger a PagerDuty event via the Events API v2."""
    payload = {
        "routing_key": integration_key,
        "event_action": "trigger",
        "payload": {
            "summary": title,
            "severity": "critical",
            "source": "zircon-impersonation",
            "custom_details": {"details": body},
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue", json=payload
            )
            resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[AlertEngine] PagerDuty dispatch failed: %s", exc)
        return False


async def _send_teams(webhook_url: str, title: str, body: str) -> bool:
    """POST an adaptive card to a Microsoft Teams Incoming Webhook."""
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "E53E3E",
        "sections": [{"text": body.replace("\n", "<br/>")}],
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[AlertEngine] Teams dispatch failed: %s", exc)
        return False


async def _send_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a Telegram message via the Bot API."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": text})
            resp.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("[AlertEngine] Telegram dispatch failed: %s", exc)
        return False


async def _dispatch_channel(channel: dict, title: str, body: str) -> bool:
    """Route a notification to the appropriate channel handler."""
    channel_type = (channel.get("type") or "").lower()
    if channel_type == "slack":
        return await _send_slack(channel.get("webhook", ""), body)
    if channel_type == "pagerduty":
        return await _send_pagerduty(channel.get("key", ""), title, body)
    if channel_type == "teams":
        return await _send_teams(channel.get("webhook", ""), title, body)
    if channel_type == "telegram":
        return await _send_telegram(
            channel.get("bot_token", ""), channel.get("chat_id", ""), body
        )
    logger.warning("[AlertEngine] Unknown channel type '%s' — skipping.", channel_type)
    return False


def _rule_matches(alert_rule: Any, finding: Any) -> bool:
    """Return True when *finding* satisfies all non-None criteria on *alert_rule*."""
    if alert_rule.match_module and finding.module != alert_rule.match_module:
        return False
    if alert_rule.match_finding_type and finding.finding_type != alert_rule.match_finding_type:
        return False
    if (finding.threat_score or 0) < (alert_rule.min_threat_score or 0):
        return False
    return True


async def dispatch_alerts(finding_id: int, db: AsyncSession | None = None) -> dict:
    """
    Check all active AlertRules against *finding_id* and dispatch notifications.

    Parameters
    ----------
    finding_id:
        ID of the ImpersonationFinding that was just created / updated.
    db:
        Optional async DB session.  If not provided, a new one is created.

    Returns
    -------
    dict with keys ``rules_checked``, ``rules_matched``, ``notifications_sent``, ``notifications_failed``.
    """
    from app.models import AlertRule, ImpersonationFinding

    stats = {
        "rules_checked": 0,
        "rules_matched": 0,
        "notifications_sent": 0,
        "notifications_failed": 0,
    }

    _own_session = db is None
    if _own_session:
        from app.database import AsyncSessionLocal
        db = AsyncSessionLocal()

    try:
        finding_row = (
            await db.execute(
                select(ImpersonationFinding).where(ImpersonationFinding.id == finding_id)
            )
        ).scalar_one_or_none()

        if not finding_row:
            logger.warning("[AlertEngine] Finding %s not found", finding_id)
            return stats

        alert_rules = (
            await db.execute(select(AlertRule).where(AlertRule.active.is_(True)))
        ).scalars().all()

        stats["rules_checked"] = len(alert_rules)
        body = _finding_to_text(finding_row)
        title = (
            f"Impersonation alert: {finding_row.module.upper()} score={finding_row.threat_score}"
        )

        for rule in alert_rules:
            if not _rule_matches(rule, finding_row):
                continue
            stats["rules_matched"] += 1
            channels: list[dict] = []
            try:
                channels = json.loads(rule.channels_json or "[]")
            except Exception:  # noqa: BLE001
                pass
            for channel in channels:
                if await _dispatch_channel(channel, title, body):
                    stats["notifications_sent"] += 1
                else:
                    stats["notifications_failed"] += 1

    finally:
        if _own_session:
            await db.close()

    return stats
