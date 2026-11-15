"""Authenticated search of Ukraine's public declaration register."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import NazkWatch, NazkWatchDocument, User
from app.schemas import NazkSearchRequest, NazkWatchCreate
from app.services.nazk import NazkSourceError, search_declarations

router = APIRouter()


@router.post("/search")
async def search(request: NazkSearchRequest, response: Response, _: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    try:
        if request.declarant_id is not None:
            return await search_declarations(request.query, request.workplace_edrpou, request.page, request.declarant_id)
        return await search_declarations(request.query, request.workplace_edrpou, request.page)
    except NazkSourceError as exc:
        raise HTTPException(status_code=502, detail=str(exc), headers={"Cache-Control": "no-store"}) from exc


def _watch_output(watch: NazkWatch) -> dict:
    return {
        "id": watch.id, "label": watch.label, "declarant_id": watch.declarant_id,
        "workplace_edrpou": watch.workplace_edrpou, "last_attempt": watch.last_attempt,
        "last_success": watch.last_success, "last_status": watch.last_status,
        "last_error": watch.last_error, "baseline_complete": watch.baseline_complete,
    }


@router.get("/watches")
async def list_watches(response: Response, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    watches = (await db.execute(select(NazkWatch).where(NazkWatch.owner_id == user.id)
                                .order_by(NazkWatch.created_at.desc()))).scalars().all()
    counts = dict((await db.execute(
        select(NazkWatchDocument.watch_id, func.count(NazkWatchDocument.id))
        .join(NazkWatch, NazkWatch.id == NazkWatchDocument.watch_id)
        .where(NazkWatch.owner_id == user.id, NazkWatchDocument.discovered_after_baseline.is_(True))
        .group_by(NazkWatchDocument.watch_id)
    )).all())
    return [{**_watch_output(watch), "new_count": counts.get(watch.id, 0)} for watch in watches]


@router.get("/watches/{watch_id}/changes")
async def watch_changes(watch_id: int, response: Response, offset: int = Query(0, ge=0),
                        db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    watch = (await db.execute(select(NazkWatch.id).where(
        NazkWatch.id == watch_id, NazkWatch.owner_id == user.id,
    ))).scalar_one_or_none()
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found",
                            headers={"Cache-Control": "no-store"})
    items = (await db.execute(select(NazkWatchDocument).where(
        NazkWatchDocument.watch_id == watch_id,
        NazkWatchDocument.discovered_after_baseline.is_(True),
    ).order_by(NazkWatchDocument.first_seen.desc(), NazkWatchDocument.id.desc())
      .offset(offset).limit(50))).scalars().all()
    return [{"document_id": item.document_id, "detected_at": item.first_seen,
             "source_url": "https://public.nazk.gov.ua/documents/" + item.document_id}
            for item in items]


@router.post("/watches", status_code=201)
async def create_watch(request: NazkWatchCreate, response: Response, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    watch = NazkWatch(owner_id=user.id, **request.model_dump())
    db.add(watch)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="This watch already exists") from exc
    await db.refresh(watch)
    return _watch_output(watch)


@router.delete("/watches/{watch_id}", status_code=204)
async def delete_watch(watch_id: int, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    watch = (await db.execute(select(NazkWatch).where(
        NazkWatch.id == watch_id, NazkWatch.owner_id == user.id,
    ))).scalar_one_or_none()
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    await db.delete(watch)
    await db.commit()
