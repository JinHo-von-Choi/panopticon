"""Shared fixtures for NetWatcher tests (PostgreSQL)."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio

from netwatcher.utils.config import Config
from netwatcher.storage.database import Database
from netwatcher.storage.schemas import ALL_SCHEMAS
from netwatcher.storage.partition_manager import (
    DEFAULT_MONTHS_AHEAD,
    PartitionManager,
)
from netwatcher.storage.repositories import (
    BlocklistRepository,
    DeviceRepository,
    EventRepository,
    IncidentRepository,
    TrafficStatsRepository,
)


# 테스트가 요구하는 DB 대상은 여기 한 곳에서만 정한다.
# Config.load()는 NETWATCHER_DB_* 환경변수를 YAML 뒤에 덮어쓰므로,
# 테스트는 그 결과를 신뢰하지 않고 로드 직후 postgresql 구간을 다시 고정한다.
_TEST_DB = {
    "host": os.environ.get("NETWATCHER_TEST_DB_HOST", "localhost"),
    "port": int(os.environ.get("NETWATCHER_TEST_DB_PORT", "5432")),
    "database": os.environ.get("NETWATCHER_TEST_DB_NAME", "netwatcher_test"),
    "username": os.environ.get("NETWATCHER_TEST_DB_USER", "netwatcher"),
    "password": os.environ.get(
        "NETWATCHER_TEST_DB_PASSWORD", os.environ.get("NETWATCHER_DB_PASSWORD", "")
    ),
}

# 이 픽스처를 요청한 테스트는 PostgreSQL 이 필요하다.
_DB_FIXTURES = frozenset(
    {"db", "event_repo", "device_repo", "stats_repo", "blocklist_repo", "incident_repo"}
)

_DB_PROBE_TIMEOUT = 5.0


def _allow_db_skip() -> bool:
    """DB 부재 시 건너뛰기를 허용할지 정한다. 기본은 허용하지 않는다."""
    return os.environ.get("NETWATCHER_TEST_ALLOW_DB_SKIP", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _postgres_available() -> bool:
    """테스트 DB에 붙을 수 있는지 한 번 확인한다."""
    async def probe() -> None:
        conn = await asyncpg.connect(
            host=_TEST_DB["host"],
            port=_TEST_DB["port"],
            database=_TEST_DB["database"],
            user=_TEST_DB["username"],
            password=_TEST_DB["password"],
            timeout=_DB_PROBE_TIMEOUT,
        )
        await conn.close()

    try:
        asyncio.run(probe())
    except Exception:
        return False
    return True


def pytest_collection_modifyitems(config, items):
    """DB가 없으면 DB가 필요한 테스트를 실패가 아니라 건너뛴다.

    기본값은 건너뛰지 않는다. DB 없는 환경에서 조용히 통과하면 CI가
    DB 테스트를 실행하지 못해도 초록이 되기 때문이다. 건너뛰기는
    ``NETWATCHER_TEST_ALLOW_DB_SKIP=1`` 로 명시적으로_opt-in_한 경우에만
    적용된다.
    """
    if not _allow_db_skip():
        return
    if _postgres_available():
        return
    reason = pytest.mark.skip(
        reason=(
            f"PostgreSQL 이 연결되지 않아 건너뛴다 "
            f"({_TEST_DB['host']}:{_TEST_DB['port']}/{_TEST_DB['database']})"
        )
    )
    for item in items:
        if _DB_FIXTURES.intersection(item.fixturenames):
            item.add_marker(reason)


@pytest.fixture(autouse=True)
def _disable_auth_env(monkeypatch):
    """테스트 환경에서 인증 환경변수를 비활성화한다.

    load_dotenv()가 .env를 다시 로드하므로, 삭제가 아닌 값 오버라이드로 처리한다.
    """
    monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "false")
    monkeypatch.setenv("NETWATCHER_SKIP_DOTENV", "1")


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """Config pointing to a test-specific PostgreSQL schema."""
    yaml_content = f"""
netwatcher:
  interface: null
  postgresql:
    enabled: true
    host: {json.dumps(_TEST_DB["host"])}
    port: {_TEST_DB["port"]}
    database: {json.dumps(_TEST_DB["database"])}
    username: {json.dumps(_TEST_DB["username"])}
    password: {json.dumps(_TEST_DB["password"])}
    pool_size: 5
    ssl_mode: "disable"
    search_path: "test_{uuid.uuid4().hex[:8]},public"
    tenant_id: ""
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
    loaded = Config.load(config_file)
    # Config.load()는 NETWATCHER_DB_* 환경변수를 YAML 뒤에 덮어쓴다.
    # 로드 직후 테스트 DB 대상을 다시 고정해 그 덮어쓰기가_TEST_DB_를
    # 바꾸지 못하게 한다.
    loaded.raw["postgresql"] = {**loaded.raw.get("postgresql", {}), **_TEST_DB}
    return loaded


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
    # 재시도 대기 없이 즉시 실패시킨다. DB가 없는 실행에서 오류마다
    # 15초씩 지연되는 것을 막는다.
    await database.connect(max_retries=1)

    # database.connect()는 더 이상 ALL_SCHEMAS를 실행하지 않으므로 직접 초기화
    async with database.pool.acquire() as conn:
        for sql in ALL_SCHEMAS:
            await conn.execute(sql)

    # events 는 월별 range 파티션 표다. 프로덕션과 같은 범위를 확보해야
    # 파티션 없는 INSERT 실패가 시험에서 그대로 드러난다.
    await PartitionManager(database.pool).ensure_partitions(DEFAULT_MONTHS_AHEAD)

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
