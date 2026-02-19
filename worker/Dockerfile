# URL-Detector/worker/Dockerfile
FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run Celery worker with info logging
CMD ["celery", "-A", "worker", "worker", "--loglevel=info"]