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

    _scheduler.add_job(_scan_monitored, IntervalTrigger(minutes=15), id="scan_monitored", replace_existing=True)
    _scheduler.start()
    print("[scheduler] Started")


def stop_scheduler():
    try:
        _scheduler.shutdown(wait=False)
    except Exception:
        pass
