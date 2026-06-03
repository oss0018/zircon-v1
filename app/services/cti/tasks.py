from app.services.cti.celery_app import celery_app
from app.services.cti.collection import collector_schedule_map


@celery_app.task(name="cti.collector.run")
def run_collector(name: str) -> dict:
    return {"collector": name, "status": "stubbed", "schedule_minutes": collector_schedule_map().get(name)}


@celery_app.task(name="cti.collectors.tick")
def tick_collectors() -> dict:
    return {"collectors": collector_schedule_map()}


celery_app.conf.beat_schedule = {
    f"cti-{collector}-schedule": {
        "task": "cti.collector.run",
        "schedule": minutes * 60,
        "args": (collector,),
    }
    for collector, minutes in collector_schedule_map().items()
}
