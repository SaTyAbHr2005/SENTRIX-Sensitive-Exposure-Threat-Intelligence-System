from celery import Celery
import os

# load Celery config from environment (or config.py) by importing app config
from app import config

broker = config.CELERY_BROKER_URL
backend = config.CELERY_RESULT_BACKEND

celery = Celery("sentrix", broker=broker, backend=backend)

# Optional: basic config
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# import tasks so celery registers them
# explicit imports to avoid autodiscovery issues inside packages
from app.blueprints.tasks import js_discovery, leak_detection, validation, risk_ml, osint_correlation  # noqa: E402,F401
