from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import MonitoringFinding, MonitoringJob, MonitoringRun, User
from app.schemas import MonitoringFindingOut, MonitoringJobCreate, MonitoringJobOut, MonitoringRunOut
from app.services.monitoring_service import (
    execute_monitoring_job,
    list_monitoring_options,
    normalize_monitoring_config,
    serialize_finding,
    serialize_monitoring_config,
    serialize_run,
)

router = APIRouter()


@router.get("/", response_model=List[MonitoringJobOut])
async def list_jobs(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(MonitoringJob).order_by(MonitoringJob.created_at.desc()))
    return result.scalars().all()


@router.get("/options")
async def get_options(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    return await list_monitoring_options(db)


@router.get("/runs", response_model=List[MonitoringRunOut])
async def list_runs(
    job_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(MonitoringRun)
    if job_id is not None:
        query = query.where(MonitoringRun.job_id == job_id)
    query = query.order_by(desc(MonitoringRun.started_at)).limit(limit)
    runs = (await db.execute(query)).scalars().all()
    return [serialize_run(run) for run in runs]


@router.get("/findings", response_model=List[MonitoringFindingOut])
async def list_findings(
    job_id: Optional[int] = Query(None),
    run_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(MonitoringFinding)
    if job_id is not None:
        query = query.where(MonitoringFinding.job_id == job_id)
    if run_id is not None:
        query = query.where(MonitoringFinding.run_id == run_id)
    if status:
        query = query.where(MonitoringFinding.status == status)
    query = query.order_by(desc(MonitoringFinding.last_seen)).limit(limit)
    findings = (await db.execute(query)).scalars().all()
    return [serialize_finding(finding) for finding in findings]


@router.post("/", response_model=MonitoringJobOut)
async def create_job(
    data: MonitoringJobCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    job = MonitoringJob(
        name=data.name,
        type=(data.type or "unified").strip().lower(),
        config_json=serialize_monitoring_config(data.config_json),
        schedule=data.schedule,
        is_active=data.is_active,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


@router.get("/{job_id}", response_model=MonitoringJobOut)
async def get_job(job_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(MonitoringJob).where(MonitoringJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    return job


@router.patch("/{job_id}", response_model=MonitoringJobOut)
async def update_job(
    job_id: int,
    data: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(MonitoringJob).where(MonitoringJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")

    for key, value in data.items():
        if key == "config_json":
            job.config_json = serialize_monitoring_config(value)
        elif key == "type":
            job.type = (value or "unified").strip().lower()
        elif hasattr(job, key):
            setattr(job, key, value)

    if "config_json" not in data and "type" not in data:
        job.config_json = serialize_monitoring_config(normalize_monitoring_config(job.type, job.config_json))

    await db.commit()
    await db.refresh(job)
    return job


@router.delete("/{job_id}")
async def delete_job(job_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(MonitoringJob).where(MonitoringJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(job)
    await db.commit()
    return {"ok": True}


@router.post("/{job_id}/trigger")
async def trigger_job(job_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(MonitoringJob).where(MonitoringJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    return await execute_monitoring_job(db, job, trigger_type="manual", preview_limit=10)
