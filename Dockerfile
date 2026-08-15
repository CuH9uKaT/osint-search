FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Reduce memory fragmentation a bit
    MALLOC_ARENA_MAX=2

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --upgrade pip && \
    python -m pip install -r requirements.txt

COPY . .

RUN useradd -m -u 10001 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 10000

# 1 Gunicorn worker + 2 threads — keep the web process small
# Sherlock child processes are separately limited by app.py
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-10000} --workers 1 --threads 2 --timeout 360 --graceful-timeout 20 --max-requests 80 --max-requests-jitter 20 --access-logfile - --error-logfile - app:app"]
