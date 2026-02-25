"""asyncpg를 통한 비동기 PostgreSQL 커넥션 풀 관리."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime

import asyncpg

from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.storage.database")


def _ts_encoder(val: datetime | str) -> str:
    """datetime 또는 ISO 문자열을 PostgreSQL timestamptz 텍스트로 인코딩한다."""
    if isinstance(val, datetime):
        return val.isoformat()
    return str(val)


async def _init_connection(conn: asyncpg.Connection) -> None:
    """풀의 각 커넥션에 타입 코덱을 초기화한다."""
    await conn.set_type_codec(
        "jsonb",
        encoder=json.dumps,
        decoder=json.loads,
        schema="pg_catalog",
    )
    await conn.set_type_codec(
        "inet",
        encoder=str,
        decoder=str,
        schema="pg_catalog",
        format="text",
    )
    await conn.set_type_codec(
        "macaddr",
        encoder=str,
        decoder=str,
        schema="pg_catalog",
        format="text",
    )
    await conn.set_type_codec(
        "timestamptz",
        encoder=_ts_encoder,
        decoder=str,
        schema="pg_catalog",
        format="text",
    )


class Database:
    """비동기 PostgreSQL 커넥션 풀 관리자."""

    def __init__(self, config: Config) -> None:
        """설정에서 PostgreSQL 접속 정보를 로드하고 풀 파라미터를 초기화한다."""
        pg = config.section("postgresql")
        self._pg_host = pg["host"]
        self._pg_port = pg["port"]
        self._pg_database = pg["database"]
        self._pg_user = pg["username"]
        self._pg_password = pg["password"]
        self._pool_size = pg.get("pool_size", 20)
        self._search_path = pg.get("search_path", "netwatcher,public")
        self._pool: asyncpg.Pool | None = None

    async def connect(self, max_retries: int = 5, base_delay: float = 1.0) -> None:
        """지수 백오프 재시도를 통해 커넥션 풀을 생성한다."""
        for attempt in range(1, max_retries + 1):
            try:
                self._pool = await asyncpg.create_pool(
                    host=self._pg_host,
                    port=self._pg_port,
                    database=self._pg_database,
                    user=self._pg_user,
                    password=self._pg_password,
                    min_size=2,
                    max_size=self._pool_size,
                    server_settings={"search_path": self._search_path},
                    init=_init_connection,
                )

                # Alembic 마이그레이션 상태를 확인한다
                async with self._pool.acquire() as conn:
                    has_alembic = await conn.fetchval(
                        "SELECT EXISTS ("
                        "  SELECT 1 FROM information_schema.tables"
                        "  WHERE table_name = 'alembic_version'"
                        ")"
                    )
                    if not has_alembic:
                        logger.warning(
                            "alembic_version 테이블이 없습니다. "
                            "'alembic upgrade head'를 실행하여 스키마를 초기화하세요. "
                            "기존 DB라면 'alembic stamp head'로 현재 상태를 마킹하세요."
                        )

                logger.info(
                    "PostgreSQL pool connected (size=%d, search_path=%s)",
                    self._pool_size,
                    self._search_path,
                )
                return
            except (asyncpg.PostgresError, OSError, ConnectionRefusedError) as exc:
                if attempt == max_retries:
                    logger.error(
                        "DB connection failed after %d attempts: %s", max_retries, exc,
                    )
                    raise
                delay = base_delay * (2 ** (attempt - 1))
                logger.warning(
                    "DB connection attempt %d/%d failed: %s — retrying in %.1fs",
                    attempt, max_retries, exc, delay,
                )
                await asyncio.sleep(delay)

    async def close(self) -> None:
        """커넥션 풀을 종료한다."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("PostgreSQL pool closed")

    @property
    def pool(self) -> asyncpg.Pool:
        """커넥션 풀을 반환한다. 미연결 시 RuntimeError를 발생시킨다."""
        if self._pool is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._pool
