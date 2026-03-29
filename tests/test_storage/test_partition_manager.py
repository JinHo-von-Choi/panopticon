"""PartitionManager 테스트: 파티션 생성/삭제/조회.

파티셔닝 마이그레이션이 실행되지 않은 상태에서의 안전한 동작도 검증한다.
"""

from __future__ import annotations

import pytest

from netwatcher.storage.partition_manager import PartitionManager


@pytest.mark.asyncio
async def test_non_partitioned_table_returns_empty(db):
    """파티셔닝되지 않은 events 테이블에서 모든 메서드가 빈 결과를 반환한다."""
    pm = PartitionManager(db.pool)

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

    # retention 90일로 삭제 — 2020년 파티션은 삭제되어야 한다
    dropped = await pm.drop_expired_partitions(retention_days=90)
    assert "events_2020_01" in dropped

    # 현재 월 파티션은 유지
    partitions = await pm.list_partitions()
    partition_names = [p["name"] for p in partitions]
    assert pname in partition_names
    assert "events_2020_01" not in partition_names
