import json
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SLAlert, SLMention, SocialListeningRule


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

        author = (mention.author_username or "").lower()
        if any(str(term).lower() in author for term in brand_terms if str(term).strip()):
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
        return alerts
