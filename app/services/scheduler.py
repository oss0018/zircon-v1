"""
APScheduler background task scheduler.
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

_scheduler = AsyncIOScheduler()


def start_scheduler():
    from app.services.indexer import scan_monitored_dir
    from app.config import settings
    from app.database import AsyncSessionLocal

    async def _scan_monitored():
        try:
            count = await scan_monitored_dir(settings.monitored_dir, AsyncSessionLocal)
            if count:
                print(f"[scheduler] Indexed {count} files from monitored dir")
        except Exception as e:
            print(f"[scheduler] Monitored scan error: {e}")

    async def _scan_all_watched_folders():
        """Scan all active watched folders for new files."""
        try:
            from app.database import AsyncSessionLocal
            from app.models import WatchedFolder
            from sqlalchemy import select
            from app.api.files import _scan_watched_folder

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(WatchedFolder).where(WatchedFolder.is_active)
                )
                folders = result.scalars().all()
                for folder in folders:
                    try:
                        await _scan_watched_folder(folder, db)
                    except Exception as e:
                        print(f"[scheduler] Error scanning {folder.path}: {e}")
        except Exception as e:
            print(f"[scheduler] Watched folder scan error: {e}")

    async def _run_scheduled_storage_sources():
        """Run indexing for all enabled storage sources whose schedule is due."""
        try:
            from app.database import AsyncSessionLocal
            from app.models import StorageSource
            from app.services.storage_indexer import run_source_indexing
            from sqlalchemy import select
            import re
            from datetime import datetime, timezone

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(StorageSource).where(
                        StorageSource.is_enabled == True,  # noqa: E712
                    )
                )
                sources = result.scalars().all()

            for source in sources:
                if source.last_run_status == "running":
                    continue  # skip already-running sources
                schedule = (source.schedule or "@hourly").strip().lower()
                if schedule == "disabled":
                    continue
                if _is_source_due(source):
                    try:
                        await run_source_indexing(source.id)
                    except Exception as exc:
                        print(f"[scheduler] Storage source {source.id} error: {exc}")
        except Exception as exc:
            print(f"[scheduler] Storage sources scan error: {exc}")

    _scheduler.add_job(_scan_monitored, IntervalTrigger(minutes=15), id="scan_monitored", replace_existing=True)
    _scheduler.add_job(_scan_all_watched_folders, IntervalTrigger(minutes=5), id="scan_watched_folders", replace_existing=True)
    _scheduler.add_job(
        _run_scheduled_storage_sources,
        IntervalTrigger(minutes=10),
        id="scan_storage_sources",
        replace_existing=True,
    )
    _scheduler.start()
    print("[scheduler] Started. Watched folder scan every 5 minutes. Storage sources schedule evaluated every 10 minutes.")


def _is_source_due(source) -> bool:
    """Return True if the source has not run recently enough given its schedule."""
    from datetime import datetime, timezone, timedelta

    schedule = (source.schedule or "@hourly").strip().lower()
    last_run = source.last_run_at

    if last_run is None:
        return True

    # Map named schedules to minute intervals
    _NAMED = {
        "@hourly": 60,
        "@daily": 1440,
        "@weekly": 10080,
    }

    if schedule in _NAMED:
        interval_minutes = _NAMED[schedule]
    else:
        # Parse simple cron: try to derive interval from */N fields
        # e.g. "*/30 * * * *" → 30 minutes
        parts = schedule.split()
        if len(parts) >= 1:
            minute_field = parts[0]
            import re
            m = re.match(r"\*/(\d+)$", minute_field)
            if m:
                interval_minutes = int(m.group(1))
            else:
                interval_minutes = 60  # default hourly for unrecognized cron
        else:
            interval_minutes = 60

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    elapsed = (now - last_run).total_seconds() / 60
    return elapsed >= interval_minutes


def stop_scheduler():
    try:
        _scheduler.shutdown(wait=False)
    except Exception:
        pass
