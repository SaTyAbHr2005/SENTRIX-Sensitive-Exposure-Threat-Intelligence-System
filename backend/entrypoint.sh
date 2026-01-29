#!/bin/sh
# entrypoint: start gunicorn web server
# this container also can run celery worker if overridden in docker-compose

# Wait for mongodb/redis if desired - light sleep (compose has depends_on)
sleep 2

# Import patterns to DB
echo "Importing leak patterns..."
python scripts/import_patterns.py

exec gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"