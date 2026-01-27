import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/sentrix")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

# request timeouts used by tasks
TASK_HTTP_TIMEOUT = int(os.getenv("TASK_HTTP_TIMEOUT", "10"))  # seconds for requests
TASK_FETCH_TIMEOUT = int(os.getenv("TASK_FETCH_TIMEOUT", "8"))