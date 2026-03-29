"""AuditLogger 테스트."""

from __future__ import annotations

import pytest
import pytest_asyncio

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
    """audit_log 테이블이 없을 때 graceful 처리."""

    @pytest.mark.asyncio
    async def test_log_without_table(self, db):
        """테이블 미존재 시 예외 없이 무시."""
        logger = AuditLogger(db.pool)
        await logger.log(user="admin", action="test", resource="/r")

    @pytest.mark.asyncio
    async def test_query_without_table(self, db):
        """테이블 미존재 시 빈 리스트 반환."""
        logger = AuditLogger(db.pool)
        results = await logger.query()
        assert results == []
