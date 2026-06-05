from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ImpersonationFinding, ThreatActor
from app.services.impersonation.threat_actor_correlator import correlate_finding, link_finding_to_actor


async def list_threat_actors(db: AsyncSession) -> list[ThreatActor]:
    return (await db.execute(select(ThreatActor).order_by(ThreatActor.last_seen.desc()))).scalars().all()


async def get_threat_actor_or_404(db: AsyncSession, actor_id: int) -> ThreatActor:
    row = (await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return row


async def create_threat_actor(db: AsyncSession, actor: ThreatActor) -> ThreatActor:
    db.add(actor)
    await db.commit()
    await db.refresh(actor)
    return actor


async def delete_threat_actor(db: AsyncSession, actor_id: int) -> None:
    row = await get_threat_actor_or_404(db, actor_id)
    await db.delete(row)
    await db.commit()


async def correlate_actor_findings(db: AsyncSession, actor_id: int) -> dict:
    actor = await get_threat_actor_or_404(db, actor_id)
    findings = (await db.execute(select(ImpersonationFinding))).scalars().all()
    matched = 0
    for finding in findings:
        matches = await correlate_finding(finding.id, db=db)
        if any(match_actor_id == actor.id for match_actor_id, _ in matches):
            await link_finding_to_actor(finding.id, actor.id, db=db)
            matched += 1
    return {"actor_id": actor.id, "matched_findings": matched}
