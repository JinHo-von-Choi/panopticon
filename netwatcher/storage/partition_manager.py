"""events 테이블의 월별 파티셔닝을 관리하는 PartitionManager."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncpg

logger = logging.getLogger("netwatcher.storage.partition_manager")

# 이번 달 파티션이 없으면 INSERT 가 실패한다. months_ahead 만큼 앞까지 미리 만든다.
DEFAULT_MONTHS_AHEAD = 3

# 지난 파티션도 필요하다.
#
# 2026-10-22 실측: EVE 수집기는 처음 설치하면 파일 바이트 0부터 읽는다
# (ingest/tailer.py 의 초기 state). 기존 eve.json 을 가리키는 새 설치는
# 과거 시각의 경보를 그대로 넣으려 한다. 그런데 파티션이 이번 달 이후만
# 있으면 그 INSERT 는 "no partition of relation "events" found for row" 로
# 실패하고, 배치 전체가 롤백되어 수집이 영구히 막힌다.
#
# 보존 기간(retention.events_days=90)만큼의 과거를 확보하면 그 구간이
# 전부 저장된다. 3개월 뒤로 확보하면 90일 치를 덮는다.
DEFAULT_MONTHS_BEHIND = 3


class PartitionUnavailableError(RuntimeError):
    """events 이번 달 파티션을 확보하지 못했을 때 발생한다."""


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

    async def ensure_partitions(self, months_ahead: int = DEFAULT_MONTHS_AHEAD,
                                months_behind: int = DEFAULT_MONTHS_BEHIND) -> list[str]:
        """현재 월 기준 앞뒤 범위의 월별 파티션을 생성한다.

        이미 존재하는 파티션은 건너뛴다. 생성된 파티션 이름 목록을 반환한다.

        ``months_behind`` 는 지난 파티션이다. 과거 시각의 기록을 저장하려면
        그 월의 파티션이 있어야 한다 — 없으면 INSERT 가 "no partition of
        relation" 로 실패하고 배치 전체가 롤백된다. 이벤트 보존 기간
        (기본 90일)을 덮을 만큼 확보한다.
        """
        if not await self._is_partitioned():
            logger.warning(
                "events 테이블이 파티셔닝되지 않았습니다. "
                "008_events_monthly_partitioning 마이그레이션을 실행하세요."
            )
            return []

        now      = datetime.now(timezone.utc)
        created  = []

        for offset in range(-months_behind, months_ahead + 1):
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

    async def partition_state(self, months_ahead: int = DEFAULT_MONTHS_AHEAD,
                              months_behind: int = DEFAULT_MONTHS_BEHIND) -> dict:
        """events 파티션의 현재 상태를 읽는다.

        DDL 권한 없이 읽을 수 있다. ``covered`` 는 지금 시각의 INSERT 가
        partitioning 관점에서 성공하는지를 뜻한다 — 파티셔닝되지 않은 테이블은
        범위 제한이 없으므로 항상 covered 다.

        ``missing`` 는 확보해야 하는 전체 창(과거 ``months_behind`` 개월 +
        미래 ``months_ahead`` 개월) 안에서 없는 파티션을 모두 담는다. 지난
        파티션이 없으면 과거 시각의 INSERT 가 실패하므로 같이 드러낸다.
        """
        partitioned = await self._is_partitioned()
        now = datetime.now(timezone.utc)
        months = [
            _partition_name(target.year, target.month)
            for target in (_add_months(now, offset)
                           for offset in range(-months_behind, months_ahead + 1))
        ]
        current = _partition_name(now.year, now.month)

        existing: set[str] = set()
        if partitioned:
            rows = await self._pool.fetch(
                """SELECT c.relname FROM pg_class c
                   JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE c.relname = ANY($1::text[])
                     AND n.nspname = current_schema()""",
                months,
            )
            existing = {row["relname"] for row in rows}

        current_exists = current in existing
        missing = [name for name in months if name not in existing]
        return {
            "partitioned": partitioned,
            "current_month": current,
            "current_month_exists": current_exists if partitioned else True,
            "covered": (not partitioned) or current_exists,
            "months": months,
            "missing": missing if partitioned else [],
        }

    async def ensure_covered(self, months_ahead: int = DEFAULT_MONTHS_AHEAD) -> dict:
        """이번 달 파티션을 확보한다.

        파티셔닝되지 않은 테이블은 범위 제한이 없으므로 그대로 통과한다.
        파티셔닝된데 이번 달 파티션을 만들지 못하면 PartitionUnavailableError 로
        알린다 — 조용히 데이터 손실을 허용하지 않는다.

        여기서는 **이번 달만** 만든다. 이 메서드는 콘솔 기동 시 호출되며
        콘솔의 DB 권한에 DDL 이 없을 수 있다. 앞뒤 전체 창은 마이그레이션
        권한으로 실행하는 ``python -m netwatcher.storage.migrate`` 가 확보한다.
        """
        state = await self.partition_state(months_ahead)
        if state["covered"]:
            return state

        month = state["current_month"]
        try:
            await self.ensure_partitions(months_ahead=0, months_behind=0)
        except Exception as exc:
            raise PartitionUnavailableError(
                f"events 파티션 {month} 을 만들 수 없습니다: "
                f"{type(exc).__name__}: {exc}. "
                "마이그레이션 권한으로 "
                "'python -m netwatcher.storage.partition_manager --ensure' 를 실행하세요."
            ) from exc

        state = await self.partition_state(months_ahead)
        if not state["covered"]:
            raise PartitionUnavailableError(
                f"events 파티션 {month} 이 여전히 없습니다. "
                "마이그레이션 권한으로 "
                "'python -m netwatcher.storage.partition_manager --ensure' 를 실행하세요."
            )
        return state

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
            if not re.fullmatch(r"events_[0-9]{4}_[0-9]{2}", name):
                continue
            try:
                parts = name.replace("events_", "").split("_")
                year  = int(parts[0])
                month = int(parts[1])
            except (IndexError, ValueError):
                continue

            # 해당 파티션의 마지막 날 = 다음 달 1일 - 1일
            try:
                part_end = _add_months(datetime(year, month, 1, tzinfo=timezone.utc), 1)
            except ValueError:
                continue
            if part_end <= cutoff:
                async with self._pool.acquire() as conn, conn.transaction():
                    for table in ("business_reviews", "case_workflows", "event_work_links", "event_ingest"):
                        await conn.execute(f"DELETE FROM {table} WHERE event_id IN (SELECT id FROM {name})")
                    await conn.execute(f"DROP TABLE IF EXISTS {name}")
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


async def _run(months: int, ensure: bool, months_behind: int = DEFAULT_MONTHS_BEHIND) -> int:
    """명령줄 처리. 이번 달 파티션이 확보되지 않으면 실패 코드를 돌려준다."""
    from netwatcher.storage.database import Database
    from netwatcher.utils.config import Config

    config = Config.load()
    database = Database(config)
    await database.connect(max_retries=1)
    try:
        manager = PartitionManager(database.pool)
        state = await manager.partition_state(months, months_behind)
        if ensure:
            try:
                created = await manager.ensure_partitions(months, months_behind)
            except Exception as exc:
                # 실패를 이어서 진행하지 않는다. 파티션 확보는 배포의 조건이며
                # 여기서 넘어가면 경보 저장이 멈춘 채로 배포가 완료된다.
                print(
                    f"파티션을 만들지 못했습니다: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
                return 1
            print(f"생성한 파티션: {', '.join(created) if created else '없음'}")
            state = await manager.partition_state(months, months_behind)
        print(json.dumps(state, ensure_ascii=False, indent=2))
        if not state["covered"]:
            print(
                f"events 이번 달 파티션({state['current_month']})이 없습니다. "
                "마이그레이션 권한으로 이 명령을 다시 실행하세요.",
                file=sys.stderr,
            )
            return 1
        return 0
    finally:
        await database.close()


def main() -> None:
    """명령줄 진입점."""
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(
        description="events 테이블의 월별 파티션 상태를 확인하고 확보한다."
    )
    parser.add_argument("--ensure", action="store_true", help="파티션을 생성한다")
    parser.add_argument(
        "--months",
        type=int,
        default=DEFAULT_MONTHS_AHEAD,
        help="몇 개월 앞까지 확보할지 (기본 3)",
    )
    parser.add_argument(
        "--months-behind",
        type=int,
        default=DEFAULT_MONTHS_BEHIND,
        help="몇 개월 뒤까지 확보할지 (기본 3 — 보존 기간만큼의 과거)",
    )
    args = parser.parse_args()
    if not 0 <= args.months <= 60:
        parser.error("--months 는 0 이상 60 이하이어야 합니다")
    if not 0 <= args.months_behind <= 60:
        parser.error("--months-behind 는 0 이상 60 이하이어야 합니다")
    raise SystemExit(asyncio.run(_run(args.months, args.ensure, args.months_behind)))


if __name__ == "__main__":
    main()
