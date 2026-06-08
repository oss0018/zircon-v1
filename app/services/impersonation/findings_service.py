from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.models import ImpersonationFinding


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _score_filter_from_severity(severity: Optional[str]) -> Optional[ColumnElement[bool]]:
    if not severity:
        return None
    normalized = severity.strip().lower()
    if normalized in {"critical", "high"}:
        return ImpersonationFinding.threat_score >= 80
    if normalized == "medium":
        return ImpersonationFinding.threat_score.between(60, 79)
    if normalized == "low":
        return ImpersonationFinding.threat_score < 60
    return None


async def list_findings(
    db: AsyncSession,
    *,
    module: Optional[str] = None,
    platform: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    min_score: int = 0,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[ImpersonationFinding], int]:
    filters = [ImpersonationFinding.threat_score >= min_score]
    if module:
        filters.append(ImpersonationFinding.module == module.strip().lower())
    if platform:
        filters.append(ImpersonationFinding.platform.ilike(f"%{platform.strip()}%"))
    if status:
        filters.append(ImpersonationFinding.status == status.strip())
    severity_filter = _score_filter_from_severity(severity)
    if severity_filter is not None:
        filters.append(severity_filter)

    total_stmt = select(func.count(ImpersonationFinding.id))
    items_stmt = select(ImpersonationFinding)
    for filter_clause in filters:
        total_stmt = total_stmt.where(filter_clause)
        items_stmt = items_stmt.where(filter_clause)

    total = (await db.execute(total_stmt)).scalar_one()
    items = (
        await db.execute(items_stmt.order_by(desc(ImpersonationFinding.last_seen)).limit(limit).offset(offset))
    ).scalars().all()
    return items, int(total)


async def get_finding_or_404(db: AsyncSession, finding_id: int) -> ImpersonationFinding:
    finding = (await db.execute(select(ImpersonationFinding).where(ImpersonationFinding.id == finding_id))).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def update_finding_status(
    db: AsyncSession,
    *,
    finding_id: int,
    status: str,
    reviewed_by: Optional[int],
    false_positive_reason: Optional[str] = None,
) -> ImpersonationFinding:
    finding = await get_finding_or_404(db, finding_id)
    finding.status = status
    finding.false_positive_reason = false_positive_reason if status == "false_positive" else None
    finding.reviewed_by = reviewed_by
    finding.reviewed_at = _utcnow()
    await db.commit()
    await db.refresh(finding)
    return finding
