from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertRule, ImpersonationFinding
from app.services.impersonation.alert_engine import dispatch_alerts


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
    return await dispatch_alerts(db, finding)
