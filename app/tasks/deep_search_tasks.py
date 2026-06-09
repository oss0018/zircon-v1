import asyncio
import os

from app.services.cti.celery_app import celery_app
from app.services.deep_search_ingestion import ingest_source

_BACKGROUND_TASKS: set[asyncio.Task] = set()


def _track_background_task(task: asyncio.Task) -> None:
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)


@celery_app.task(name="deep_search.ingest_source", queue="celery_deepsearch")
def ingest_source_task(source_id: int, triggered_by: str = "scheduler", user_id: int | None = None) -> dict:
    return asyncio.run(ingest_source(source_id, triggered_by=triggered_by, user_id=user_id))


def enqueue_ingest_source(source_id: int, *, triggered_by: str = "scheduler", user_id: int | None = None) -> dict:
    if os.getenv("CELERY_BROKER_URL") or os.getenv("CTI_CELERY_BROKER_URL"):
        ingest_source_task.delay(source_id, triggered_by=triggered_by, user_id=user_id)
        return {"queued": True, "mode": "celery"}
    task = asyncio.create_task(ingest_source(source_id, triggered_by=triggered_by, user_id=user_id))
    _track_background_task(task)
    return {"queued": True, "mode": "asyncio"}
