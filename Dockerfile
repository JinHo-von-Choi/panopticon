FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

RUN mkdir -p data/logs data/pcaps data/threatfeeds data/extracted

EXPOSE 38585

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:38585/health || exit 1

# DB 마이그레이션: docker compose run --rm db-migrate
ENTRYPOINT ["python", "-m", "netwatcher"]

FROM base AS native
CMD ["--component", "sensor"]

FROM base AS unprivileged
RUN groupadd --gid 10001 panopticon && \
    useradd --uid 10001 --gid 10001 --no-create-home panopticon && \
    chown -R 10001:10001 /app/data
USER 10001:10001

FROM unprivileged AS native-console
CMD ["--component", "console"]

FROM unprivileged AS eve
