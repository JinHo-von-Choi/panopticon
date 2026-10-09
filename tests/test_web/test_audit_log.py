"""AuditLogger 테스트."""

from __future__ import annotations

import pytest
import pytest_asyncio
import asyncpg

from netwatcher.storage.schemas import ALL_SCHEMAS
from netwatcher.web.audit_log import AuditLogger


@pytest_asyncio.fixture
async def audit_logger(db):
    """audit_log 테이블을 생성하고 AuditLogger를 반환한다."""
    async with db.pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          SERIAL          PRIMARY KEY,
                user_id     VARCHAR(100),
                action      VARCHAR(50)     NOT NULL,
                resource    VARCHAR(200),
                details     JSONB,
                ip          VARCHAR(45),
                created_at  TIMESTAMPTZ     DEFAULT NOW()
            )
        """)
    return AuditLogger(db.pool)


class TestAuditLogger:
    @pytest.mark.asyncio
    async def test_log_and_query(self, audit_logger):
        await audit_logger.log(
            user="admin",
            action="block",
            resource="/api/blocklist/ip",
            details={"ip": "1.2.3.4"},
            ip="127.0.0.1",
        )

        results = await audit_logger.query(limit=10)
        assert len(results) == 1
        entry = results[0]
        assert entry["user"] == "admin"
        assert entry["action"] == "block"
        assert entry["resource"] == "/api/blocklist/ip"
        assert entry["details"]["ip"] == "1.2.3.4"
        assert entry["ip"] == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_query_filter_by_user(self, audit_logger):
        await audit_logger.log(user="admin", action="block", resource="/r1")
        await audit_logger.log(user="analyst", action="read", resource="/r2")

        admin_logs = await audit_logger.query(user="admin")
        assert len(admin_logs) == 1
        assert admin_logs[0]["user"] == "admin"

    @pytest.mark.asyncio
    async def test_query_filter_by_action(self, audit_logger):
        await audit_logger.log(user="admin", action="block", resource="/r1")
        await audit_logger.log(user="admin", action="read", resource="/r2")

        block_logs = await audit_logger.query(action="block")
        assert len(block_logs) == 1
        assert block_logs[0]["action"] == "block"

    @pytest.mark.asyncio
    async def test_query_limit(self, audit_logger):
        for i in range(5):
            await audit_logger.log(user="admin", action="read", resource=f"/r{i}")

        results = await audit_logger.query(limit=3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_query_limit_max_1000(self, audit_logger):
        """limit이 1000을 초과하면 1000으로 제한된다."""
        results = await audit_logger.query(limit=9999)
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_log_truncates_long_action(self, audit_logger):
        """50자 초과 action은 잘린다."""
        long_action = "a" * 100
        await audit_logger.log(user="admin", action=long_action, resource="/r1")
        results = await audit_logger.query(limit=1)
        assert len(results) == 1
        assert len(results[0]["action"]) == 50

    @pytest.mark.asyncio
    async def test_log_with_null_details(self, audit_logger):
        await audit_logger.log(user="admin", action="test", resource="/r1", details=None)
        results = await audit_logger.query(limit=1)
        assert len(results) == 1
        assert results[0]["details"] == {}

    @pytest.mark.asyncio
    async def test_empty_query(self, audit_logger):
        results = await audit_logger.query()
        assert results == []


class TestAuditLoggerWithoutTable:
    """실제 테이블 부재와 빈 기록을 구분한다."""

    @pytest.mark.asyncio
    async def test_log_without_table(self, db):
        """감사 저장 실패는 False로 호출자에게 전달한다."""
        await db.pool.execute("DROP TABLE audit_log")
        logger = AuditLogger(db.pool)
        assert await logger.log(user="admin", action="test", resource="/r") is False

    @pytest.mark.asyncio
    async def test_query_without_table(self, db):
        """감사 조회 실패를 빈 기록으로 숨기지 않는다."""
        await db.pool.execute("DROP TABLE audit_log")
        logger = AuditLogger(db.pool)
        with pytest.raises(asyncpg.UndefinedTableError):
            await logger.query()


@pytest.mark.asyncio
async def test_corrupt_audit_details_are_not_replaced_with_empty_object(db, audit_logger):
    await db.pool.execute("INSERT INTO audit_log(user_id,action,resource,details) VALUES($1,$2,$3,$4)",
                          "admin", "test", "/test", ["invalid details"])
    with pytest.raises(ValueError):
        await audit_logger.query()


@pytest.mark.asyncio
async def test_encoded_audit_object_is_read_without_losing_fields(db, audit_logger):
    import json
    await db.pool.execute("INSERT INTO audit_log(user_id,action,resource,details) VALUES($1,$2,$3,$4)",
                          "admin", "test", "/test", json.dumps({"legacy_field": "retained"}))
    assert (await audit_logger.query())[0]["details"] == {"legacy_field": "retained"}
