"""events 테이블의 월별 파티셔닝을 관리하는 PartitionManager."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncpg

logger = logging.getLogger("netwatcher.storage.partition_manager")


def _add_months(dt: datetime, months: int) -> datetime:
    """datetime에 월을 더한다. 표준 라이브러리만 사용한다."""
    month = dt.month - 1 + months
    year  = dt.year + month // 12
    month = month % 12 + 1
    return dt.replace(year=year, month=month, day=1)


def _month_start(year: int, month: int) -> str:
    """YYYY-MM-DD 형식의 월 시작일을 반환한다."""
    return f"{year:04d}-{month:02d}-01"


def _partition_name(year: int, month: int) -> str:
    """파티션 테이블 이름을 반환한다. 예: events_2026_03"""
    return f"events_{year:04d}_{month:02d}"


class PartitionManager:
    """events 테이블의 월별 range 파티션을 생성/삭제/조회한다.

    events 테이블이 파티셔닝되지 않은 상태(마이그레이션 미실행)일 경우
    모든 메서드가 안전하게 빈 결과를 반환하거나 경고만 출력한다.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        """asyncpg 커넥션 풀을 주입받아 초기화한다."""
        self._pool = pool

    async def _is_partitioned(self) -> bool:
        """events 테이블이 파티셔닝되어 있는지 확인한다."""
        result = await self._pool.fetchval(
            """SELECT EXISTS (
                SELECT 1 FROM pg_partitioned_table pt
                JOIN pg_class c ON c.oid = pt.partrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = 'events'
                  AND n.nspname = current_schema()
            )"""
        )
        return bool(result)

    async def ensure_partitions(self, months_ahead: int = 2) -> list[str]:
        """현재 월부터 months_ahead 개월 후까지 파티션을 생성한다.

        이미 존재하는 파티션은 건너뛴다. 생성된 파티션 이름 목록을 반환한다.
        """
        if not await self._is_partitioned():
            logger.warning(
                "events 테이블이 파티셔닝되지 않았습니다. "
                "008_events_monthly_partitioning 마이그레이션을 실행하세요."
            )
            return []

        now      = datetime.now(timezone.utc)
        created  = []

        for offset in range(months_ahead + 1):
            target = _add_months(now, offset)
            name   = _partition_name(target.year, target.month)
            start  = _month_start(target.year, target.month)
            nxt    = _add_months(target, 1)
            end    = _month_start(nxt.year, nxt.month)

            # 이미 존재하면 건너뛴다
            exists = await self._pool.fetchval(
                """SELECT EXISTS (
                    SELECT 1 FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relname = $1
                      AND n.nspname = current_schema()
                )""",
                name,
            )
            if exists:
                continue

            await self._pool.execute(
                f"CREATE TABLE IF NOT EXISTS {name} "
                f"PARTITION OF events FOR VALUES FROM ('{start}') TO ('{end}')"
            )
            created.append(name)
            logger.info("파티션 생성: %s [%s, %s)", name, start, end)

        return created

    async def drop_expired_partitions(self, retention_days: int = 90) -> list[str]:
        """retention_days보다 오래된 파티션을 삭제한다. 삭제된 파티션 이름을 반환한다."""
        if not await self._is_partitioned():
            return []

        cutoff  = datetime.now(timezone.utc) - timedelta(days=retention_days)
        dropped = []

        partitions = await self._list_partition_info()
        for part in partitions:
            # 파티션 이름에서 연월을 파싱: events_YYYY_MM
            name = part["name"]
            try:
                parts = name.replace("events_", "").split("_")
                year  = int(parts[0])
                month = int(parts[1])
            except (IndexError, ValueError):
                continue

            # 해당 파티션의 마지막 날 = 다음 달 1일 - 1일
            part_end = _add_months(datetime(year, month, 1, tzinfo=timezone.utc), 1)
            if part_end <= cutoff:
                await self._pool.execute(f"DROP TABLE IF EXISTS {name}")
                dropped.append(name)
                logger.info("만료 파티션 삭제: %s", name)

        return dropped

    async def list_partitions(self) -> list[dict]:
        """모든 파티션의 이름, 행 수, 크기 정보를 반환한다."""
        if not await self._is_partitioned():
            return []
        return await self._list_partition_info()

    async def _list_partition_info(self) -> list[dict]:
        """파티션 테이블 목록을 pg_inherits에서 조회한다."""
        rows = await self._pool.fetch(
            """SELECT
                   child.relname                                       AS name,
                   pg_catalog.pg_table_size(child.oid)                 AS size_bytes,
                   child.reltuples::bigint                             AS estimated_rows
               FROM pg_inherits
               JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
               JOIN pg_class child  ON child.oid  = pg_inherits.inhrelid
               JOIN pg_namespace n  ON n.oid      = parent.relnamespace
               WHERE parent.relname = 'events'
                 AND n.nspname = current_schema()
               ORDER BY child.relname"""
        )
        return [
            {
                "name": row["name"],
                "size_bytes": row["size_bytes"],
                "estimated_rows": row["estimated_rows"],
            }
            for row in rows
        ]
