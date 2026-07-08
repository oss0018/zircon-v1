from __future__ import annotations

import logging

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertRule, ImpersonationFinding
from app.services.impersonation.alert_engine import dispatch_alerts

logger = logging.getLogger(__name__)

_ALERTABLE_FINDING_STATUSES = {"new", "under_review", "takedown_requested"}


async def list_alert_rules(db: AsyncSession) -> list[AlertRule]:
    return (await db.execute(select(AlertRule).order_by(AlertRule.name))).scalars().all()


async def get_alert_rule_or_404(db: AsyncSession, rule_id: int) -> AlertRule:
    row = (await db.execute(select(AlertRule).where(AlertRule.id == rule_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return row


async def create_alert_rule(db: AsyncSession, rule: AlertRule) -> AlertRule:
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def delete_alert_rule(db: AsyncSession, rule_id: int) -> None:
    row = await get_alert_rule_or_404(db, rule_id)
    await db.delete(row)
    await db.commit()


async def dispatch_for_finding(db: AsyncSession, finding: ImpersonationFinding) -> dict:
    if not finding.id:
        return {"skipped": True, "reason": "missing_finding_id"}
    if finding.status not in _ALERTABLE_FINDING_STATUSES:
        return {"skipped": True, "reason": f"status:{finding.status}"}
    try:
        stats = await dispatch_alerts(finding_id=finding.id, db=db)
        await db.commit()
        return stats
    except Exception as exc:
        # Intentional broad catch: alert dispatch must never break finding create/update flows.
        await db.rollback()
        logger.exception(
            "[ImpersonationAlertService] Dispatch failed for finding=%s: %s",
            finding.id,
            exc,
        )
        return {"skipped": True, "reason": "dispatch_error", "error": str(exc)}
