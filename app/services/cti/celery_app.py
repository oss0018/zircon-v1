from celery import Celery
from os import getenv

celery_app = Celery("zircon_cti")
celery_app.conf.update(
    broker_url=getenv("CTI_CELERY_BROKER_URL", "redis://redis:6379/1"),
    result_backend=getenv("CTI_CELERY_RESULT_BACKEND", "redis://redis:6379/1"),
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
)
