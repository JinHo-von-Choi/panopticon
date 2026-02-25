FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/logs data/pcaps data/threatfeeds data/extracted

EXPOSE 38585

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:38585/health || exit 1

# DB 마이그레이션: docker compose run --rm db-migrate
ENTRYPOINT ["python", "-m", "netwatcher"]
