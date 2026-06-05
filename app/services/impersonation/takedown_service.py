from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import TakedownRequest


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def list_takedowns(
    db: AsyncSession,
    *,
    status: Optional[str] = None,
    platform: Optional[str] = None,
) -> list[TakedownRequest]:
    stmt = select(TakedownRequest).order_by(desc(TakedownRequest.created_at))
    if status:
        stmt = stmt.where(TakedownRequest.status == status.strip())
    if platform:
        stmt = stmt.where(TakedownRequest.target_platform.ilike(f"%{platform.strip()}%"))
    return (await db.execute(stmt)).scalars().all()


async def get_takedown_or_404(db: AsyncSession, takedown_id: int) -> TakedownRequest:
    row = (await db.execute(select(TakedownRequest).where(TakedownRequest.id == takedown_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Takedown request not found")
    return row


async def update_takedown(
    db: AsyncSession,
    *,
    takedown_id: int,
    status: Optional[str] = None,
    notes: Optional[str] = None,
    submitted_by: Optional[int] = None,
) -> TakedownRequest:
    row = await get_takedown_or_404(db, takedown_id)
    if status is not None:
        normalized = "resolved" if status == "completed" else status
        row.status = normalized
        if normalized == "submitted":
            row.submitted_at = _utcnow()
            row.submitted_by = submitted_by
        if normalized == "resolved":
            row.resolved_at = _utcnow()
    if notes is not None:
        row.notes = notes
    await db.commit()
    await db.refresh(row)
    return row
