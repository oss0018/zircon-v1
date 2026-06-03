import asyncio
import json
import logging
import re
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SLAlert, SLMention, SocialListeningRule

logger = logging.getLogger(__name__)
_PENDING_NOTIFY_TASKS: set[asyncio.Task] = set()


def _on_notify_task_done(task: asyncio.Task) -> None:
    _PENDING_NOTIFY_TASKS.discard(task)
    if task.cancelled():
        return
    try:
        exc = task.exception()
    except Exception as err:
        logger.warning("social listening: failed reading notification task result: %s", err)
        return
    if exc:
        logger.warning("social listening: notification task failed: %s", exc)


class AlertEngine:
    """
    After NLP processing, evaluate whether a mention triggers an alert.
    """

    async def evaluate(self, mention: SLMention, rule: SocialListeningRule, db: AsyncSession):
        alerts: list[SLAlert] = []

        first_on_platform = await db.execute(
            select(SLMention.id)
            .where(
                SLMention.rule_id == rule.id,
                SLMention.source_platform == mention.source_platform,
                SLMention.id != mention.id,
            )
            .limit(1)
        )
        if not first_on_platform.scalar_one_or_none():
            alerts.append(
                SLAlert(
                    rule_id=rule.id,
                    mention_id=mention.id,
                    alert_type="FIRST_MENTION",
                    severity=mention.severity,
                    title=f"First mention on {mention.source_platform}",
                    body=(mention.content_raw or "")[:1000],
                )
            )

        if mention.severity >= 4:
            alerts.append(
                SLAlert(
                    rule_id=rule.id,
                    mention_id=mention.id,
                    alert_type="NEGATIVE_SPIKE",
                    severity=mention.severity,
                    title="High-severity negative mention",
                    body=(mention.content_raw or "")[:1000],
                )
            )

        indicators = {}
        try:
            indicators = json.loads(mention.threat_indicators_json or "{}")
        except Exception:
            indicators = {}
        if indicators.get("emails"):
            alerts.append(
                SLAlert(
                    rule_id=rule.id,
                    mention_id=mention.id,
                    alert_type="CREDENTIAL_LEAK",
                    severity=max(mention.severity, 4),
                    title="Potential credential leak detected",
                    body=(mention.content_raw or "")[:1000],
                )
            )

        brand_terms = []
        try:
            brand_terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            brand_terms = []

        author = mention.author_username or ""
        if any(
            re.search(rf"(?<![a-zA-Z0-9]){re.escape(str(term).strip())}(?![a-zA-Z0-9])", author, re.IGNORECASE)
            for term in brand_terms
            if str(term).strip()
        ):
            alerts.append(
                SLAlert(
                    rule_id=rule.id,
                    mention_id=mention.id,
                    alert_type="IMPERSONATION",
                    severity=max(mention.severity, 3),
                    title="Potential impersonation detected",
                    body=(mention.content_raw or "")[:1000],
                )
            )

        for alert in alerts:
            db.add(alert)

        if alerts:
            from app.services.notifications import notify

            alert_email = getattr(rule, "alert_email", "") or ""
            alert_telegram = getattr(rule, "alert_telegram", "") or ""
            if alert_email or alert_telegram:
                titles = [a.title for a in alerts]
                combined_title = titles[0] if len(titles) == 1 else f"{len(alerts)} alerts — {titles[0]}"
                snippet = (mention.content_raw or "")[:300]
                body_text = (
                    f"Rule: {rule.name}\n"
                    f"Platform: {mention.source_platform}\n"
                    f"Severity: {mention.severity}\n"
                    f"URL: {mention.source_url}\n\n"
                    f"{snippet}"
                )
                try:
                    task = asyncio.create_task(notify(combined_title, body_text, alert_email, alert_telegram))
                    _PENDING_NOTIFY_TASKS.add(task)
                    task.add_done_callback(_on_notify_task_done)
                except Exception as exc:
                    logger.warning("social listening: failed to schedule notification task: %s", exc)
        return alerts
