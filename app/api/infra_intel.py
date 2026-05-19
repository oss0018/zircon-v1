"""
Infrastructure Intelligence API — `/api/v1/infra`
"""
import json
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db, AsyncSessionLocal
from app.models import InfraFinding, InfraInvestigation, User
from app.services.infrastructure_intelligence import InfraOrchestrator

router = APIRouter()

_VALID_TARGET_TYPES = {"domain", "ip", "cidr", "asn", "org"}
_VALID_MODULES = {"dns", "network", "cert", "cloud"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    target: str
    target_type: str = "domain"
    modules: List[str] = ["dns", "network", "cert", "cloud"]


class InvestigateResponse(BaseModel):
    investigation_id: int
    target: str
    target_type: str
    status: str
    message: str


# ── Background task wrapper ───────────────────────────────────────────────────

async def _run_investigation_bg(
    investigation_id: int,
    target: str,
    target_type: str,
    modules: list[str],
) -> None:
    """Runs inside a BackgroundTask — opens its own DB session."""
    async with AsyncSessionLocal() as db:
        orchestrator = InfraOrchestrator()
        try:
            await orchestrator.run_investigation(
                investigation_id=investigation_id,
                target=target,
                target_type=target_type,
                modules=modules,
                db=db,
            )
        except Exception:
            pass  # orchestrator already marks status=failed and re-raises internally


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/investigate", response_model=InvestigateResponse, status_code=202)
async def start_investigation(
    body: InvestigateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Create a new infrastructure investigation and kick it off in the background."""
    if body.target_type not in _VALID_TARGET_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_type '{body.target_type}'. Must be one of: {sorted(_VALID_TARGET_TYPES)}",
        )
    invalid_modules = set(body.modules) - _VALID_MODULES
    if invalid_modules:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid modules: {sorted(invalid_modules)}. Must be subset of: {sorted(_VALID_MODULES)}",
        )
    if not body.modules:
        raise HTTPException(status_code=400, detail="At least one module must be specified")

    investigation = InfraInvestigation(
        target=body.target[:512],
        target_type=body.target_type,
        modules_json=json.dumps(body.modules),
        status="pending",
    )
    db.add(investigation)
    await db.commit()
    await db.refresh(investigation)

    background_tasks.add_task(
        _run_investigation_bg,
        investigation.id,
        body.target,
        body.target_type,
        body.modules,
    )

    return InvestigateResponse(
        investigation_id=investigation.id,
        target=investigation.target,
        target_type=investigation.target_type,
        status=investigation.status,
        message="Investigation queued and running in background",
    )


@router.get("/investigations")
async def list_investigations(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List investigations (most recent first), no findings in list view."""
    result = await db.execute(
        select(InfraInvestigation)
        .order_by(InfraInvestigation.created_at.desc())
        .limit(min(limit, 200))
        .offset(offset)
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "target": r.target,
            "target_type": r.target_type,
            "status": r.status,
            "summary_json": json.loads(r.summary_json or "{}"),
            "modules": json.loads(r.modules_json or "[]"),
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return a full investigation with all findings."""
    result = await db.execute(
        select(InfraInvestigation).where(InfraInvestigation.id == investigation_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Investigation not found")

    finding_result = await db.execute(
        select(InfraFinding)
        .where(InfraFinding.investigation_id == investigation_id)
        .order_by(InfraFinding.severity.desc())
    )
    findings = finding_result.scalars().all()

    return {
        "id": row.id,
        "target": row.target,
        "target_type": row.target_type,
        "status": row.status,
        "modules": json.loads(row.modules_json or "[]"),
        "summary_json": json.loads(row.summary_json or "{}"),
        "error_message": row.error_message,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "findings": [
            {
                "id": f.id,
                "module": f.module,
                "finding_type": f.finding_type,
                "entity": f.entity,
                "severity": f.severity,
                "source": f.source,
                "data_json": json.loads(f.data_json or "{}"),
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ],
    }


@router.delete("/investigations/{investigation_id}")
async def delete_investigation(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Delete investigation and cascade-delete all findings."""
    result = await db.execute(
        select(InfraInvestigation).where(InfraInvestigation.id == investigation_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.delete(row)
    await db.commit()
    return {"ok": True}


@router.get("/investigations/{investigation_id}/summary")
async def get_investigation_summary(
    investigation_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return a summary with findings grouped by module and severity counts."""
    result = await db.execute(
        select(InfraInvestigation).where(InfraInvestigation.id == investigation_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Investigation not found")

    finding_result = await db.execute(
        select(InfraFinding)
        .where(InfraFinding.investigation_id == investigation_id)
        .order_by(InfraFinding.severity.desc())
    )
    findings = finding_result.scalars().all()

    findings_by_module: dict[str, list] = {}
    severity_counts: dict[int, int] = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}

    for f in findings:
        module_list = findings_by_module.setdefault(f.module, [])
        module_list.append({
            "id": f.id,
            "finding_type": f.finding_type,
            "entity": f.entity,
            "severity": f.severity,
            "source": f.source,
            "data_json": json.loads(f.data_json or "{}"),
        })
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1

    return {
        "investigation_id": row.id,
        "target": row.target,
        "status": row.status,
        "summary_json": json.loads(row.summary_json or "{}"),
        "findings_by_module": findings_by_module,
        "severity_counts": severity_counts,
    }
