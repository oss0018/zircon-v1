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
                        StorageSource.is_enabled.is_(True),
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

    async def _run_scheduled_monitoring_jobs():
        """Run enabled monitoring jobs whose schedule is due."""
        try:
            from app.database import AsyncSessionLocal
            from app.models import MonitoringJob
            from app.services.monitoring_service import execute_monitoring_job, is_monitoring_job_due
            from sqlalchemy import select

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(MonitoringJob).where(MonitoringJob.is_active.is_(True))
                )
                jobs = result.scalars().all()

                for job in jobs:
                    if not is_monitoring_job_due(job):
                        continue
                    try:
                        await execute_monitoring_job(db, job, trigger_type="scheduled", preview_limit=5)
                    except Exception as exc:
                        print(f"[scheduler] Monitoring job {job.id} error: {exc}")
        except Exception as exc:
            print(f"[scheduler] Monitoring scheduler error: {exc}")

    async def _run_social_listening_rules():
        """Run active social listening rules every 15 minutes."""
        try:
            from app.database import AsyncSessionLocal
            from app.models import SocialListeningRule
            from app.services.social_listening.collector import SocialListeningCollector
            from sqlalchemy import select

            collector = SocialListeningCollector()
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SocialListeningRule).where(SocialListeningRule.active.is_(True))
                )
                rules = result.scalars().all()

                for rule in rules:
                    try:
                        summary = await collector.run_rule(rule, db)
                        print(
                            f"[scheduler] Social listening rule {rule.id}: "
                            f"checked={summary.get('checked', 0)} new={summary.get('new', 0)}"
                        )
                    except Exception as exc:
                        print(f"[scheduler] Social listening rule {rule.id} error: {exc}")
        except Exception as exc:
            print(f"[scheduler] Social listening scheduler error: {exc}")

    async def _run_lookalike_alerts():
        """Dispatch look-alike domain alerts every 30 minutes."""
        try:
            from datetime import timedelta
            from app.database import AsyncSessionLocal
            from app.models import LookalikeRule, LookalikeDomain
            from app.services.lookalike.alert_engine import dispatch_lookalike_alerts
            from sqlalchemy import select
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).replace(tzinfo=None)
            cutoff = now - timedelta(hours=2)

            async with AsyncSessionLocal() as db:
                rules_res = await db.execute(
                    select(LookalikeRule).where(LookalikeRule.active.is_(True))
                )
                rules = rules_res.scalars().all()

                for rule in rules:
                    try:
                        domains_res = await db.execute(
                            select(LookalikeDomain).where(
                                LookalikeDomain.rule_id == rule.id,
                                LookalikeDomain.status == "registered",
                                LookalikeDomain.threat_score >= 50,
                                LookalikeDomain.last_checked_at >= cutoff,
                            )
                        )
                        domains = list(domains_res.scalars().all())
                        if not domains:
                            continue
                        summary = await dispatch_lookalike_alerts(rule.id, domains, db)
                        print(
                            f"[scheduler] Lookalike alerts rule {rule.id}: "
                            f"sent={summary.get('sent', 0)} failed={summary.get('failed', 0)}"
                        )
                    except Exception as exc:
                        print(f"[scheduler] Lookalike alert rule {rule.id} error: {exc}")
        except Exception as exc:
            print(f"[scheduler] Lookalike alerts scheduler error: {exc}")

    _scheduler.add_job(_scan_monitored, IntervalTrigger(minutes=15), id="scan_monitored", replace_existing=True, max_instances=1, misfire_grace_time=60)
    _scheduler.add_job(_scan_all_watched_folders, IntervalTrigger(minutes=8), id="scan_watched_folders", replace_existing=True, max_instances=1, misfire_grace_time=60)
    _scheduler.add_job(
        _run_scheduled_storage_sources,
        IntervalTrigger(minutes=11),
        id="scan_storage_sources",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        _run_scheduled_monitoring_jobs,
        IntervalTrigger(minutes=6),
        id="run_monitoring_jobs",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        _run_social_listening_rules,
        IntervalTrigger(minutes=15),
        id="run_social_listening_rules",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )
    _scheduler.add_job(
        _run_lookalike_alerts,
        IntervalTrigger(minutes=30),
        id="run_lookalike_alerts",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )
    _scheduler.start()
    print("[scheduler] Started. Monitored dir scan every 15 minutes. Watched folder scan every 8 minutes. Storage sources are evaluated every 11 minutes. Monitoring jobs are evaluated every 6 minutes. Social listening rules are evaluated every 15 minutes.")


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
