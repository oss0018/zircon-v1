from celery import Celery

celery_app = Celery("zircon_cti")
celery_app.conf.update(
    broker_url="redis://redis:6379/1",
    result_backend="redis://redis:6379/1",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
)
