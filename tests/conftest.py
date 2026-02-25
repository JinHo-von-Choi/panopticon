"""Shared fixtures for NetWatcher tests (PostgreSQL)."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from netwatcher.utils.config import Config
from netwatcher.storage.database import Database
from netwatcher.storage.schemas import ALL_SCHEMAS
from netwatcher.storage.repositories import (
    BlocklistRepository,
    DeviceRepository,
    EventRepository,
    IncidentRepository,
    TrafficStatsRepository,
)


@pytest.fixture(autouse=True)
def _disable_auth_env(monkeypatch):
    """테스트 환경에서 인증 환경변수를 비활성화한다.
    load_dotenv()가 .env를 다시 로드하므로, 삭제가 아닌 값 오버라이드로 처리한다.
    """
    monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "false")


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """Config pointing to a test-specific PostgreSQL schema."""
    yaml_content = f"""
netwatcher:
  interface: null
  postgresql:
    enabled: true
    host: "localhost"
    port: 35432
    database: "bee_db"
    username: "bee"
    password: "{os.environ.get('NETWATCHER_DB_PASSWORD', '')}"
    pool_size: 5
    ssl_mode: "disable"
    search_path: "test_{uuid.uuid4().hex[:8]},public"
  auth:
    enabled: false
    username: "admin"
    password: ""
    token_expire_hours: 24
  logging:
    level: DEBUG
    directory: "{tmp_path / 'logs'}"
  alerts:
    rate_limit:
      window_seconds: 300
      max_per_key: 5
    channels: {{}}
  whitelist:
    ips: []
    ip_ranges: []
    macs: []
    domains: []
    domain_suffixes: [".local", ".internal"]
  engines:
    arp_spoof:
      enabled: true
      gratuitous_window_seconds: 30
      gratuitous_threshold: 10
      cooldown_seconds: 300
    dns_anomaly:
      enabled: true
      max_label_length: 50
      max_subdomain_depth: 5
      entropy_threshold: 3.5
      high_volume_threshold: 200
      high_volume_window_seconds: 60
    port_scan:
      enabled: true
      window_seconds: 60
      threshold: 15
      alerted_cooldown_seconds: 300
      max_tracked_connections: 10000
    http_suspicious:
      enabled: true
      beacon_window_seconds: 3600
      max_tracked_pairs: 5000
    traffic_anomaly:
      enabled: true
      warmup_ticks: 30
      z_score_threshold: 3.0
      host_eviction_seconds: 86400
    threat_intel:
      enabled: true
    icmp_anomaly:
      enabled: true
      ping_sweep_threshold: 20
      ping_sweep_window_seconds: 30
      flood_threshold: 100
      flood_window_seconds: 1
    dhcp_spoof:
      enabled: true
      starvation_threshold: 50
      starvation_window_seconds: 60
    lateral_movement:
      enabled: true
      lateral_ports: [22, 445, 3389, 135, 5985]
      unique_host_threshold: 5
      window_seconds: 300
      chain_depth_threshold: 3
    data_exfil:
      enabled: true
      byte_threshold: 104857600
      window_seconds: 3600
      dns_txt_size_threshold: 500
    protocol_anomaly:
      enabled: true
      ttl_change_threshold: 10
      min_ttl_samples: 5
    mac_spoof:
      enabled: true
      max_ips_per_mac: 5
      ip_window_seconds: 300
    signature:
      enabled: true
      rules_dir: "config/rules"
      hot_reload: false
"""
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(yaml_content)
    return Config.load(config_file)


@pytest_asyncio.fixture
async def db(config: Config) -> Database:
    """Create a test-specific PostgreSQL schema and tear it down after tests."""
    search_path = config.get("postgresql.search_path", "")
    schema_name = search_path.split(",")[0].strip()

    # Create the test schema directly via asyncpg
    pg = config.section("postgresql")
    conn_kwargs = dict(
        host=pg["host"], port=pg["port"], database=pg["database"],
        user=pg["username"], password=pg["password"],
    )
    admin_conn = await asyncpg.connect(**conn_kwargs)
    try:
        await admin_conn.execute(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")
    finally:
        await admin_conn.close()

    database = Database(config)
    await database.connect()

    # database.connect()는 더 이상 ALL_SCHEMAS를 실행하지 않으므로 직접 초기화
    async with database.pool.acquire() as conn:
        for sql in ALL_SCHEMAS:
            await conn.execute(sql)

    yield database
    await database.close()

    # Drop the test schema
    admin_conn = await asyncpg.connect(**conn_kwargs)
    try:
        await admin_conn.execute(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE")
    finally:
        await admin_conn.close()


@pytest_asyncio.fixture
async def event_repo(db: Database) -> EventRepository:
    return EventRepository(db)


@pytest_asyncio.fixture
async def device_repo(db: Database) -> DeviceRepository:
    return DeviceRepository(db)


@pytest_asyncio.fixture
async def stats_repo(db: Database) -> TrafficStatsRepository:
    return TrafficStatsRepository(db)


@pytest_asyncio.fixture
async def blocklist_repo(db: Database) -> BlocklistRepository:
    return BlocklistRepository(db)


@pytest_asyncio.fixture
async def incident_repo(db: Database) -> IncidentRepository:
    return IncidentRepository(db)
