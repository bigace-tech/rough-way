#!/bin/bash
export PYTHONPATH=/app
export FLASK_APP=app.py
export FLASK_ENV=production
export PORT="${PORT:-8080}"

exec gunicorn app:app \
    --bind "0.0.0.0:$PORT" \
    --workers 4 \
    --threads 2 \
    --worker-class gthread \
    --worker-connections 1000 \
    --timeout 300 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --access-logfile - \
    --error-logfile - \
    --log-level debug