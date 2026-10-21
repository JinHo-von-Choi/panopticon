"""PartitionManager 테스트: 파티션 생성/삭제/조회/상태 확인.

파티셔닝 마이그레이션이 실행되지 않은 상태에서의 안전한 동작도 검증한다.
"""

from __future__ import annotations

from datetime import datetime, timezone

import asyncpg
import pytest

from netwatcher.storage.partition_manager import (
    PartitionManager,
    PartitionUnavailableError,
)


PARTITIONED_EVENTS_DDL = """
    CREATE TABLE events (
        id          BIGSERIAL       NOT NULL,
        timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
        engine      VARCHAR(64)     NOT NULL,
        severity    VARCHAR(16)     NOT NULL,
        title       VARCHAR(512)    NOT NULL,
        description TEXT            NOT NULL DEFAULT '',
        source_ip   INET,
        source_mac  MACADDR,
        dest_ip     INET,
        dest_mac    MACADDR,
        title_key        TEXT,
        description_key  TEXT,
        metadata         JSONB           NOT NULL DEFAULT '{}',
        packet_info      JSONB           NOT NULL DEFAULT '{}',
        resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
        reasoning        TEXT,
        mitre_attack_id  VARCHAR(64),
        threat_level     SMALLINT        NOT NULL DEFAULT 0,
        PRIMARY KEY (id, timestamp)
    ) PARTITION BY RANGE (timestamp)
"""

# 마이그레이션 008 이 실행되지 않은 상태 — 파티셔닝되지 않은 표.
UNPARTITIONED_EVENTS_DDL = """
    CREATE TABLE events (
        id          BIGSERIAL       PRIMARY KEY,
        timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
        engine      VARCHAR(64)     NOT NULL,
        severity    VARCHAR(16)     NOT NULL,
        title       VARCHAR(512)    NOT NULL,
        description TEXT            NOT NULL DEFAULT '',
        source_ip   INET,
        source_mac  MACADDR,
        dest_ip     INET,
        dest_mac    MACADDR,
        title_key        TEXT,
        description_key  TEXT,
        metadata         JSONB           NOT NULL DEFAULT '{}',
        packet_info      JSONB           NOT NULL DEFAULT '{}',
        resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
        reasoning        TEXT,
        mitre_attack_id  VARCHAR(64),
        threat_level     SMALLINT        NOT NULL DEFAULT 0
    )
"""


@pytest.mark.asyncio
async def test_non_partitioned_table_returns_empty(db):
    """파티셔닝되지 않은 events 테이블에서 모든 메서드가 빈 결과를 반환한다."""
    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(UNPARTITIONED_EVENTS_DDL)

    pm = PartitionManager(pool)

    partitions = await pm.list_partitions()
    assert partitions == []

    created = await pm.ensure_partitions(months_ahead=2)
    assert created == []

    dropped = await pm.drop_expired_partitions(retention_days=90)
    assert dropped == []


@pytest.mark.asyncio
async def test_ensure_partitions_on_partitioned_table(db):
    """파티셔닝된 events 테이블에서 파티션을 생성한다."""
    pool = db.pool

    # 기존 events 테이블을 파티셔닝 테이블로 재생성
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute("""
            CREATE TABLE events (
                id          BIGSERIAL       NOT NULL,
                timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
                engine      VARCHAR(64)     NOT NULL,
                severity    VARCHAR(16)     NOT NULL,
                title       VARCHAR(512)    NOT NULL,
                description TEXT            NOT NULL DEFAULT '',
                source_ip   INET,
                source_mac  MACADDR,
                dest_ip     INET,
                dest_mac    MACADDR,
                title_key        TEXT,
                description_key  TEXT,
                metadata         JSONB           NOT NULL DEFAULT '{}',
                packet_info      JSONB           NOT NULL DEFAULT '{}',
                resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
                reasoning        TEXT,
                mitre_attack_id  VARCHAR(64),
                threat_level     SMALLINT        NOT NULL DEFAULT 0,
                PRIMARY KEY (id, timestamp)
            ) PARTITION BY RANGE (timestamp)
        """)

    pm = PartitionManager(pool)

    created = await pm.ensure_partitions(months_ahead=1)
    assert len(created) >= 1  # 최소 현재 월 + 1개월

    # 동일 호출 시 이미 존재하므로 생성 없음
    created_again = await pm.ensure_partitions(months_ahead=1)
    assert len(created_again) == 0

    partitions = await pm.list_partitions()
    assert len(partitions) >= 1
    for p in partitions:
        assert "name" in p
        assert "size_bytes" in p
        assert "estimated_rows" in p


@pytest.mark.asyncio
async def test_drop_expired_partitions(db):
    """retention_days보다 오래된 파티션이 삭제된다."""
    pool = db.pool

    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute("""
            CREATE TABLE events (
                id          BIGSERIAL       NOT NULL,
                timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
                engine      VARCHAR(64)     NOT NULL,
                severity    VARCHAR(16)     NOT NULL,
                title       VARCHAR(512)    NOT NULL,
                description TEXT            NOT NULL DEFAULT '',
                source_ip   INET,
                source_mac  MACADDR,
                dest_ip     INET,
                dest_mac    MACADDR,
                title_key        TEXT,
                description_key  TEXT,
                metadata         JSONB           NOT NULL DEFAULT '{}',
                packet_info      JSONB           NOT NULL DEFAULT '{}',
                resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
                reasoning        TEXT,
                mitre_attack_id  VARCHAR(64),
                threat_level     SMALLINT        NOT NULL DEFAULT 0,
                PRIMARY KEY (id, timestamp)
            ) PARTITION BY RANGE (timestamp)
        """)
        # 아주 오래된 파티션 생성 (2020년 1월)
        await conn.execute(
            "CREATE TABLE events_2020_01 PARTITION OF events "
            "FOR VALUES FROM ('2020-01-01') TO ('2020-02-01')"
        )
        # 현재 월 파티션도 생성
        from datetime import datetime, timezone
        from netwatcher.storage.partition_manager import _add_months
        now = datetime.now(timezone.utc)
        month_start = f"{now.year:04d}-{now.month:02d}-01"
        nxt = _add_months(now, 1)
        month_end = f"{nxt.year:04d}-{nxt.month:02d}-01"
        pname = f"events_{now.year:04d}_{now.month:02d}"
        await conn.execute(
            f"CREATE TABLE {pname} PARTITION OF events "
            f"FOR VALUES FROM ('{month_start}') TO ('{month_end}')"
        )

    pm = PartitionManager(pool)

    # 파티션 삭제 실패 때 판정·인계 삭제도 함께 되돌아가야 한다.
    import asyncpg
    event_id = await pool.fetchval("""INSERT INTO events(timestamp,engine,severity,title)
        VALUES('2020-01-10','test','WARNING','old event') RETURNING id""")
    await pool.execute("""INSERT INTO case_workflows(event_id,version,owner,status,actor,updated_at)
        VALUES($1,1,'operator','investigating','admin',NOW())""", event_id)
    await pool.execute("""INSERT INTO case_history(event_id,version,owner,status,note,actor,updated_at)
        VALUES($1,1,'operator','investigating','retain note','admin',NOW())""", event_id)
    await pool.execute("""INSERT INTO business_reviews(event_id,version,decision,note,actor,scope,reviewed_at)
        VALUES($1,1,'investigate','retain review','admin','{}',NOW())""", event_id)
    await pool.execute("""CREATE TABLE partition_retention_guard (
        event_id BIGINT,event_timestamp TIMESTAMPTZ,
        FOREIGN KEY(event_id,event_timestamp) REFERENCES events_2020_01(id,timestamp))""")
    with pytest.raises(asyncpg.DependentObjectsStillExistError):
        await pm.drop_expired_partitions(retention_days=90)
    for table in ('events','business_reviews','case_workflows','case_history'):
        assert await pool.fetchval(f'SELECT count(*) FROM {table}') == 1
    await pool.execute('DROP TABLE partition_retention_guard')

    # retention 90일로 삭제 — 2020년 파티션과 연결 기록은 삭제되어야 한다.
    dropped = await pm.drop_expired_partitions(retention_days=90)
    for table in ('business_reviews','case_workflows','case_history'):
        assert await pool.fetchval(f'SELECT count(*) FROM {table}') == 0
    assert "events_2020_01" in dropped

    # 현재 월 파티션은 유지
    partitions = await pm.list_partitions()
    partition_names = [p["name"] for p in partitions]
    assert pname in partition_names
    assert "events_2020_01" not in partition_names


@pytest.mark.asyncio
async def test_partition_state_on_non_partitioned_table(db):
    """파티셔닝되지 않은 테이블은 범위 제한이 없으므로 항상 확보된 것으로 본다."""
    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(UNPARTITIONED_EVENTS_DDL)

    state = await PartitionManager(pool).partition_state()

    assert state["partitioned"] is False
    assert state["covered"] is True
    assert state["current_month_exists"] is True
    assert state["missing"] == []


@pytest.mark.asyncio
async def test_partition_state_reports_missing_current_month(db):
    """이번 달 파티션이 없으면 covered 가 거짓이 된다."""
    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(PARTITIONED_EVENTS_DDL)

    pm = PartitionManager(pool)
    state = await pm.partition_state()
    assert state["partitioned"] is True
    assert state["current_month_exists"] is False
    assert state["covered"] is False
    assert state["current_month"] in state["missing"]


@pytest.mark.asyncio
async def test_ensure_covered_creates_current_month_partition(db):
    """ensure_covered 는 이번 달 파티션을 만들어 확보 상태로 만든다."""
    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(PARTITIONED_EVENTS_DDL)

    pm = PartitionManager(pool)
    state = await pm.ensure_covered()

    assert state["covered"] is True
    assert state["current_month_exists"] is True
    assert state["current_month"] not in state["missing"]


@pytest.mark.asyncio
async def test_ensure_covered_raises_when_partition_cannot_be_created(db, monkeypatch):
    """파티션을 만들 수 없으면 조용히 넘어가지 않고 알린다."""
    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(PARTITIONED_EVENTS_DDL)

    pm = PartitionManager(pool)

    async def refuse(months_ahead: int = 2) -> list[str]:
        raise PermissionError("permission denied for schema")

    monkeypatch.setattr(pm, "ensure_partitions", refuse)

    with pytest.raises(PartitionUnavailableError) as error:
        await pm.ensure_covered()

    assert "partition_manager" in str(error.value)


@pytest.mark.asyncio
async def test_insert_fails_without_matching_partition(db):
    """파티션이 없는 월의 INSERT 는 실패한다 — 확보가 필요한 이유를 고정한다."""
    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(PARTITIONED_EVENTS_DDL)
        await conn.execute(
            "CREATE TABLE events_2020_01 PARTITION OF events "
            "FOR VALUES FROM ('2020-01-01') TO ('2020-02-01')"
        )

    with pytest.raises(asyncpg.exceptions.CheckViolationError) as error:
        await pool.execute(
            "INSERT INTO events(timestamp,engine,severity,title) "
            "VALUES(NOW(),'test','WARNING','event')"
        )
    assert "no partition of relation" in str(error.value)


# ── 시험 스키마가 프로덕션과 같은 형태인지 ─────────────────────────
#
# 2026-10-22 실측: 정적 DDL (storage/schemas.py) 은 월별 파티션 이름을
# 모르므로 events_default (DEFAULT 파티션) 를 함께 만든다. 프로덕션에는
# 이 파티션이 없다. 시험 스키마에 기본 파티션이 남으면 "파티션 없는 월의
# INSERT 실패" 를 시험이 재현하지 못한다 — 프로덕션에서 멈추는 수집이
# 시험에서는 통과해 보인다. 시험 픽스처는 이 파티션을 제거한다.

@pytest.mark.asyncio
async def test_test_schema_has_no_default_partition(db):
    """시험 스키마에는 events 의 DEFAULT 파티션이 없다 — 프로덕션과 같다."""
    exists = await db.pool.fetchval(
        """SELECT EXISTS (
               SELECT 1 FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE c.relname = 'events_default'
                 AND n.nspname = current_schema()
           )"""
    )

    assert exists is False, (
        "시험 스키마에 events_default 가 있다 — 프로덕션에는 없는 파티션이 "
        "시험에서만 INSERT 실패를 가린다"
    )


@pytest.mark.asyncio
async def test_insert_outside_covered_window_fails(db):
    """보장 범위 밖 시각의 INSERT 는 프로덕션과 똑같이 실패한다."""
    with pytest.raises(asyncpg.exceptions.CheckViolationError) as error:
        await db.pool.execute(
            "INSERT INTO events(timestamp,engine,severity,title) "
            "VALUES('2020-01-10','test','WARNING','out of range')"
        )

    assert "no partition of relation" in str(error.value)


@pytest.mark.asyncio
async def test_past_window_is_covered(db):
    """보존 기간 안의 과거 시각은 저장된다.

    EVE 수집기는 처음 설치하면 파일 바이트 0부터 읽는다. 그 경로로 들어온
    과거 경보가 "no partition of relation" 로 막히면 수집이 영구히 멈춘다.
    """
    from datetime import timedelta

    stale = datetime.now(timezone.utc) - timedelta(days=40)

    event_id = await db.pool.fetchval(
        """INSERT INTO events(timestamp,engine,severity,title)
           VALUES($1,'test','WARNING','retained event') RETURNING id""",
        stale,
    )

    assert event_id is not None


@pytest.mark.asyncio
async def test_ensure_partitions_covers_past_months(db):
    """ensure_partitions 는 과거 파티션도 만든다."""
    from netwatcher.storage.partition_manager import (
        DEFAULT_MONTHS_BEHIND,
        _add_months,
        _partition_name,
    )

    pool = db.pool
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS events CASCADE")
        await conn.execute(PARTITIONED_EVENTS_DDL)

    created = await PartitionManager(pool).ensure_partitions(months_ahead=1, months_behind=2)

    now = datetime.now(timezone.utc)
    past = _partition_name(*(_add_months(now, -2).year, _add_months(now, -2).month))
    assert past in created, "과거 파티션이 만들어지지 않았다"

    partitions = await PartitionManager(pool).list_partitions()
    names = [p["name"] for p in partitions]
    assert past in names
