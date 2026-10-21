"""스키마 마이그레이션과 events 월별 파티션 확보를 함께 수행한다.

배포 경로의 마이그레이션 단계는 이 모듈을 거친다. 마이그레이션만으로는
events 월별 파티션이 미래까지 확보되지 않는다 — 파티션 생성 범위는
마이그레이션 실행 시점의 현재 월을 기준으로 하기 때문이다. 충분한 개월을
미리 확보해 두지 않으면 그 다음 달부터 INSERT 가 실패한다.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys


def _run_alembic() -> None:
    """alembic upgrade head 를 현재 작업 디렉터리에서 실행한다."""
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
        check=True,
        cwd=os.getcwd(),
    )


def _load_config():
    """설정을 읽는다. search_path 는 alembic 과 같은 순서로 정한다."""
    from netwatcher.utils.config import Config

    config = Config.load()
    search_path = os.environ.get("NETWATCHER_DB_SEARCH_PATH")
    if search_path:
        config.raw.setdefault("postgresql", {})["search_path"] = search_path
    return config


async def _ensure_partitions() -> int:
    """events 월별 파티션을 확보한다. 이번 달 파티션이 없으면 실패한다."""
    from netwatcher.storage.database import Database
    from netwatcher.storage.partition_manager import DEFAULT_MONTHS_AHEAD, PartitionManager

    config = _load_config()
    database = Database(config)
    await database.connect(max_retries=1)
    try:
        manager = PartitionManager(database.pool)
        try:
            created = await manager.ensure_partitions(DEFAULT_MONTHS_AHEAD)
        except Exception as exc:
            # 파티션 확보 실패를 넘어가면 배포가 성공한 것처럼 보이지만
            # 경보 저장은 멈춘다. 배포를 실패시킨다.
            print(
                f"events 파티션을 만들지 못했습니다: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 1
        state = await manager.partition_state(DEFAULT_MONTHS_AHEAD)
    finally:
        await database.close()

    if created:
        print(f"생성한 파티션: {', '.join(created)}")
    if not state["covered"]:
        print(
            f"events 이번 달 파티션({state['current_month']})을 확보하지 못했습니다",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> None:
    """명령줄 진입점."""
    _run_alembic()
    raise SystemExit(asyncio.run(_ensure_partitions()))


if __name__ == "__main__":
    main()
