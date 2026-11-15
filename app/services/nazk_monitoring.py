"""Scheduled NACP watches, with a complete baseline before alerts."""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import NamedTuple
from uuid import uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import NazkWatch, NazkWatchDocument, Notification
from app.services.nazk import NazkSourceError, search_declarations

logger = logging.getLogger(__name__)
MAX_PAGES = 100


class WatchTarget(NamedTuple):
    declarant_id: int | None
    workplace_edrpou: str | None


async def _snapshot(watch: WatchTarget) -> set[str]:
    async def fetch(page):
        return await search_declarations(None, watch.workplace_edrpou, page, watch.declarant_id)

    first = await fetch(1)
    count = first["count"]
    pages = max(1, (count + 99) // 100)
    if pages > MAX_PAGES:
        raise NazkSourceError("More than 10,000 records match; NACP exposes only the first 100 pages")
    documents: set[str] = set()
    for page in range(1, pages + 1):
        result = first if page == 1 else await fetch(page)
        if result["count"] != count:
            raise NazkSourceError("NACP results changed during the check; retrying on the next run")
        for record in result["results"]:
            if watch.declarant_id and record["declarant_id"] != watch.declarant_id:
                raise NazkSourceError("NACP returned a record for a different or unknown declarant")
            documents.add(record["id"])
    if len(documents) != count:
        raise NazkSourceError("NACP returned incomplete or duplicate results; no baseline was updated")
    if pages > 1:
        verify = await fetch(1)
        if verify["count"] != count or [r["id"] for r in verify["results"]] != [r["id"] for r in first["results"]]:
            raise NazkSourceError("NACP results changed during the check; retrying on the next run")
    return documents


async def run_watch(db: AsyncSession, watch_id: int) -> bool:
    now = datetime.now(timezone.utc)
    token = uuid4().hex
    claimed = await db.execute(
        update(NazkWatch)
        .where(
            NazkWatch.id == watch_id,
            or_(NazkWatch.lease_until.is_(None), NazkWatch.lease_until < now),
            or_(NazkWatch.last_attempt.is_(None), NazkWatch.last_attempt <= now - timedelta(days=1)),
        )
        .values(last_attempt=now, last_status="running", last_error=None,
                lease_until=now + timedelta(minutes=15), lease_token=token)
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    if not claimed.rowcount:
        return False
    watch = (await db.execute(select(NazkWatch).where(
        NazkWatch.id == watch_id, NazkWatch.lease_token == token,
    ))).scalar_one_or_none()
    if watch is None:
        await db.rollback()
        return False
    await db.refresh(watch)
    target = WatchTarget(watch.declarant_id, watch.workplace_edrpou)
    await db.rollback()

    try:
        document_ids = await asyncio.wait_for(_snapshot(target), timeout=600)
        # Acquire a write lock, including on SQLite where SELECT FOR UPDATE is ignored.
        locked = await db.execute(update(NazkWatch).where(
            NazkWatch.id == watch_id,
            NazkWatch.lease_token == token,
            NazkWatch.lease_until > datetime.now(timezone.utc),
        ).values(last_status="running").execution_options(synchronize_session=False))
        if not locked.rowcount:
            await db.rollback()
            return False
        watch = (await db.execute(select(NazkWatch).where(
            NazkWatch.id == watch_id, NazkWatch.lease_token == token,
        ).execution_options(populate_existing=True))).scalar_one()
        existing = set((await db.execute(select(NazkWatchDocument.document_id).where(
            NazkWatchDocument.watch_id == watch_id,
        ))).scalars())
        new_ids = document_ids - existing
        db.add_all([
            NazkWatchDocument(watch_id=watch_id, document_id=doc_id,
                              discovered_after_baseline=watch.baseline_complete)
            for doc_id in new_ids
        ])
        if watch.baseline_complete and new_ids:
            # Notifications are shared across users; keep watch details in the owner's view.
            db.add(Notification(type="info", title="NACP watch update",
                                message="A declaration watch has new matches. Open Legal & Regulatory to review your watches."))
        watch.baseline_complete = True
        watch.last_success = datetime.now(timezone.utc)
        watch.last_status = "success"
        watch.last_error = None
        watch.lease_until = None
        watch.lease_token = None
        await db.commit()
    except (NazkSourceError, TimeoutError) as exc:
        await db.rollback()
        await _fail_claim(db, watch_id, token,
                          str(exc) if isinstance(exc, NazkSourceError) else "NACP check timed out")
    except Exception:
        await db.rollback()
        logger.exception("NACP watch %s failed", watch_id)
        await _fail_claim(db, watch_id, token, "NACP check failed unexpectedly; see server logs")
    return True


async def _fail_claim(db: AsyncSession, watch_id: int, token: str, message: str) -> None:
    await db.execute(update(NazkWatch).where(
        NazkWatch.id == watch_id, NazkWatch.lease_token == token,
    ).values(last_status="failed", last_error=message, lease_until=None, lease_token=None)
      .execution_options(synchronize_session=False))
    await db.commit()


async def run_due_watches(db: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    await db.execute(
        update(NazkWatch)
        .where(NazkWatch.last_status == "running", NazkWatch.lease_until < now)
        .values(last_status="failed", last_error="NACP check was interrupted", lease_until=None, lease_token=None)
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    ids = (await db.execute(select(NazkWatch.id).where(
        or_(NazkWatch.last_attempt.is_(None), NazkWatch.last_attempt <= now - timedelta(days=1)),
        or_(NazkWatch.lease_until.is_(None), NazkWatch.lease_until < now),
    ))).scalars().all()
    for watch_id in ids:
        await run_watch(db, watch_id)
