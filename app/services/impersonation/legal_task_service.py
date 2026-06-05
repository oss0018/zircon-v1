from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import LegalTask


async def list_legal_tasks(db: AsyncSession) -> list[LegalTask]:
    return (await db.execute(select(LegalTask).order_by(desc(LegalTask.created_at)))).scalars().all()


async def get_legal_task_or_404(db: AsyncSession, task_id: int) -> LegalTask:
    row = (await db.execute(select(LegalTask).where(LegalTask.id == task_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Legal task not found")
    return row


async def create_legal_task(db: AsyncSession, task: LegalTask) -> LegalTask:
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return task


async def delete_legal_task(db: AsyncSession, task_id: int) -> None:
    row = await get_legal_task_or_404(db, task_id)
    await db.delete(row)
    await db.commit()
