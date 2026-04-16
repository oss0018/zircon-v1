from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, MonitoringJob
from app.schemas import MonitoringJobCreate, MonitoringJobOut

router = APIRouter()


@router.get("/", response_model=List[MonitoringJobOut])
async def list_jobs(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(MonitoringJob).order_by(MonitoringJob.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=MonitoringJobOut)
async def create_job(data: MonitoringJobCreate, db: AsyncSession = Depends(get_db),
                     _: User = Depends(get_current_user)):
    job = MonitoringJob(
        name=data.name,
        type=data.type,
        config_json=data.config_json,
        schedule=data.schedule,
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
async def update_job(job_id: int, data: dict, db: AsyncSession = Depends(get_db),
                     _: User = Depends(get_current_user)):
    result = await db.execute(select(MonitoringJob).where(MonitoringJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")
    for key, value in data.items():
        if hasattr(job, key):
            setattr(job, key, value)
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
    """Manually trigger a monitoring job."""
    result = await db.execute(select(MonitoringJob).where(MonitoringJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Not found")

    import json
    config = {}
    try:
        config = json.loads(job.config_json)
    except Exception:
        pass

    run_result = {"job_id": job_id, "type": job.type, "status": "triggered", "config": config}

    # Perform basic action depending on job type
    if job.type == "folder_scan":
        from app.services.indexer import scan_monitored_dir
        from app.config import settings
        folder = config.get("folder", settings.monitored_dir)
        count = await scan_monitored_dir(folder, None)
        run_result["indexed"] = count

    job.last_run = datetime.utcnow()
    await db.commit()
    return run_result
