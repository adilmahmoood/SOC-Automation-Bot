from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "soc_bot",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.core.tasks"],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task behavior
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,

    # Result expiry (24h)
    result_expires=86400,

    # Retry policy
    task_max_retries=3,
    task_default_retry_delay=5,

    # Routes
    task_routes={
        "app.core.tasks.process_alert": {"queue": "alerts"},
    },
)
