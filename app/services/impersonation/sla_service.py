from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ServiceLevelAgreement


async def list_slas(db: AsyncSession) -> list[ServiceLevelAgreement]:
    return (await db.execute(select(ServiceLevelAgreement).order_by(ServiceLevelAgreement.name))).scalars().all()


async def get_sla_or_404(db: AsyncSession, sla_id: int) -> ServiceLevelAgreement:
    row = (await db.execute(select(ServiceLevelAgreement).where(ServiceLevelAgreement.id == sla_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="SLA not found")
    return row


async def create_sla(db: AsyncSession, sla: ServiceLevelAgreement) -> ServiceLevelAgreement:
    db.add(sla)
    await db.commit()
    await db.refresh(sla)
    return sla


def compute_sla_compliance(
    *,
    detected_at: Optional[datetime],
    triaged_at: Optional[datetime],
    takedown_completed_at: Optional[datetime],
    resolved_at: Optional[datetime],
    policy: ServiceLevelAgreement,
) -> dict:
    def _minutes(start: Optional[datetime], end: Optional[datetime]) -> Optional[int]:
        if not start or not end:
            return None
        return int((end - start).total_seconds() // 60)

    detect_min = _minutes(detected_at, triaged_at)
    takedown_min = _minutes(triaged_at, takedown_completed_at)
    resolve_min = _minutes(detected_at, resolved_at)
    return {
        "detect_sla_met": detect_min is None or detect_min <= policy.time_to_detect_min,
        "triage_sla_met": detect_min is None or detect_min <= policy.time_to_triage_min,
        "takedown_sla_met": takedown_min is None or takedown_min <= policy.time_to_takedown_min,
        "resolve_sla_met": resolve_min is None or resolve_min <= policy.time_to_resolve_min,
    }
