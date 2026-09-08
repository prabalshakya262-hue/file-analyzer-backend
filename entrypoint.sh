#!/bin/sh
# Start Celery worker in background
celery -A app.celery_app.celery_app worker --loglevel=info --concurrency=2 &

# Start Uvicorn (FastAPI) in foreground
uvicorn app.main:app --host 0.0.0.0 --port 8000