from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ImpersonationRule


async def list_rules(db: AsyncSession) -> list[ImpersonationRule]:
    return (await db.execute(select(ImpersonationRule).order_by(desc(ImpersonationRule.created_at)))).scalars().all()


async def get_rule_or_404(db: AsyncSession, rule_id: int) -> ImpersonationRule:
    row = (await db.execute(select(ImpersonationRule).where(ImpersonationRule.id == rule_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    return row


async def create_rule(db: AsyncSession, rule: ImpersonationRule) -> ImpersonationRule:
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def delete_rule(db: AsyncSession, rule_id: int) -> None:
    row = await get_rule_or_404(db, rule_id)
    await db.delete(row)
    await db.commit()
