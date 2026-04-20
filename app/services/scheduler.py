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
                    select(WatchedFolder).where(WatchedFolder.is_active == True)
                )
                folders = result.scalars().all()
                for folder in folders:
                    try:
                        await _scan_watched_folder(folder, db)
                    except Exception as e:
                        print(f"[scheduler] Error scanning {folder.path}: {e}")
        except Exception as e:
            print(f"[scheduler] Watched folder scan error: {e}")

    _scheduler.add_job(_scan_monitored, IntervalTrigger(minutes=15), id="scan_monitored", replace_existing=True)
    _scheduler.add_job(_scan_all_watched_folders, IntervalTrigger(minutes=5), id="scan_watched_folders", replace_existing=True)
    _scheduler.start()
    print("[scheduler] Started. Watched folder scan every 5 minutes.")


def stop_scheduler():
    try:
        _scheduler.shutdown(wait=False)
    except Exception:
        pass
