from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.api.auth import get_current_user
from app.database import get_db
from app.models import (User, File, Integration, WatchlistItem, MonitoringJob,
                        BrandAlert, Notification, SearchLog)
from app.schemas import DashboardStats

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_stats(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    total_files = await db.scalar(select(func.count(File.id))) or 0
    indexed_files = await db.scalar(select(func.count(File.id)).where(File.indexed == True)) or 0
    total_searches = await db.scalar(select(func.count(SearchLog.id))) or 0
    active_integrations = await db.scalar(select(func.count(Integration.id)).where(Integration.is_active == True)) or 0
    watchlist_items = await db.scalar(select(func.count(WatchlistItem.id))) or 0
    active_monitoring = await db.scalar(select(func.count(MonitoringJob.id)).where(MonitoringJob.is_active == True)) or 0
    brand_alerts_new = await db.scalar(select(func.count(BrandAlert.id)).where(BrandAlert.status == "new")) or 0
    unread_notifications = await db.scalar(select(func.count(Notification.id)).where(Notification.read == False)) or 0

    recent_searches_result = await db.execute(
        select(SearchLog).order_by(desc(SearchLog.created_at)).limit(10)
    )
    recent_searches = [
        {"query": s.query, "results_count": s.results_count,
         "source": s.source, "created_at": s.created_at.isoformat()}
        for s in recent_searches_result.scalars().all()
    ]

    # File type distribution
    from app.models import File as FileModel
    from pathlib import Path
    files_result = await db.execute(select(FileModel.name))
    file_types: dict = {}
    for (name,) in files_result.all():
        ext = Path(name).suffix.lower().lstrip(".") or "other"
        file_types[ext] = file_types.get(ext, 0) + 1

    return DashboardStats(
        total_files=total_files,
        indexed_files=indexed_files,
        total_searches=total_searches,
        active_integrations=active_integrations,
        watchlist_items=watchlist_items,
        active_monitoring_jobs=active_monitoring,
        brand_alerts_new=brand_alerts_new,
        unread_notifications=unread_notifications,
        recent_searches=recent_searches,
        file_types=file_types,
    )


@router.get("/notifications")
async def get_notifications(limit: int = 50, db: AsyncSession = Depends(get_db),
                             _: User = Depends(get_current_user)):
    result = await db.execute(
        select(Notification).order_by(desc(Notification.created_at)).limit(limit)
    )
    notifications = result.scalars().all()
    return [
        {"id": n.id, "type": n.type, "title": n.title, "message": n.message,
         "read": n.read, "created_at": n.created_at.isoformat()}
        for n in notifications
    ]


@router.post("/notifications/{notification_id}/read")
async def mark_read(notification_id: int, db: AsyncSession = Depends(get_db),
                    _: User = Depends(get_current_user)):
    result = await db.execute(select(Notification).where(Notification.id == notification_id))
    notification = result.scalar_one_or_none()
    if notification:
        notification.read = True
        await db.commit()
    return {"ok": True}


@router.post("/notifications/read-all")
async def mark_all_read(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Notification).where(Notification.read == False))
    for n in result.scalars().all():
        n.read = True
    await db.commit()
    return {"ok": True}
