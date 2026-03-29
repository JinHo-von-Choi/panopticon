"""헬스체크 테스트: 컴포넌트 상태 확인."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, PropertyMock

import pytest
import pytest_asyncio

from netwatcher.observability.health import HealthChecker


class TestHealthChecker:
    """HealthChecker 테스트 스위트."""

    @pytest.mark.asyncio
    async def test_all_unconfigured(self) -> None:
        """모든 컴포넌트가 미설정일 때 healthy를 반환하는지 검증한다."""
        checker = HealthChecker()
        result  = await checker.check_all()

        assert result["overall_status"] == "healthy"
        assert result["version"] is not None
        assert result["uptime_seconds"] >= 0
        assert "components" in result

        # 미설정 컴포넌트는 unconfigured
        for comp in result["components"].values():
            assert comp["status"] in ("healthy", "unconfigured")

    @pytest.mark.asyncio
    async def test_healthy_database(self) -> None:
        """데이터베이스가 정상일 때 healthy 상태를 반환하는지 검증한다."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=1)

        mock_pool = MagicMock()
        mock_pool.get_size.return_value = 10
        mock_pool.get_idle_size.return_value = 5

        # async context manager for pool.acquire()
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__  = AsyncMock(return_value=False)
        mock_pool.acquire.return_value = mock_ctx

        mock_db      = MagicMock()
        mock_db.pool = mock_pool

        checker = HealthChecker(database=mock_db)
        result  = await checker.check_all()

        assert result["components"]["database"]["status"] == "healthy"
        assert result["components"]["database"]["pool_size"] == 10

    @pytest.mark.asyncio
    async def test_unhealthy_database(self) -> None:
        """데이터베이스 연결 실패 시 unhealthy 상태를 반환하는지 검증한다."""
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(side_effect=ConnectionError("refused"))

        mock_pool = MagicMock()
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_ctx.__aexit__  = AsyncMock(return_value=False)
        mock_pool.acquire.return_value = mock_ctx

        mock_db      = MagicMock()
        mock_db.pool = mock_pool

        checker = HealthChecker(database=mock_db)
        result  = await checker.check_all()

        assert result["components"]["database"]["status"] == "unhealthy"
        assert result["overall_status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_sniffer_running(self) -> None:
        """스니퍼가 실행 중일 때 healthy를 반환하는지 검증한다."""
        mock_sniffer = MagicMock()
        mock_sniffer.running = True

        checker = HealthChecker(sniffer=mock_sniffer)
        result  = await checker.check_all()

        assert result["components"]["sniffer"]["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_sniffer_stopped(self) -> None:
        """스니퍼가 중지 상태일 때 unhealthy를 반환하는지 검증한다."""
        mock_sniffer = MagicMock()
        mock_sniffer.running = False

        checker = HealthChecker(sniffer=mock_sniffer)
        result  = await checker.check_all()

        assert result["components"]["sniffer"]["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_engine_registry(self) -> None:
        """엔진 레지스트리 상태가 올바르게 보고되는지 검증한다."""
        mock_engine_a = MagicMock()
        mock_engine_a.enabled = True
        mock_engine_b = MagicMock()
        mock_engine_b.enabled = False

        mock_registry = MagicMock()
        mock_registry._engines = {"a": mock_engine_a, "b": mock_engine_b}

        checker = HealthChecker(registry=mock_registry)
        result  = await checker.check_all()

        eng = result["components"]["engines"]
        assert eng["status"] == "healthy"
        assert eng["total"] == 2
        assert eng["enabled"] == 1

    @pytest.mark.asyncio
    async def test_alert_queue_depth(self) -> None:
        """알림 큐 깊이가 올바르게 보고되는지 검증한다."""
        mock_queue = MagicMock()
        mock_queue.qsize.return_value = 50
        mock_queue.maxsize = 10000

        mock_dispatcher               = MagicMock()
        mock_dispatcher._queue         = mock_queue
        mock_dispatcher._ws_subscribers = {1, 2, 3}

        checker = HealthChecker(dispatcher=mock_dispatcher)
        result  = await checker.check_all()

        aq = result["components"]["alert_queue"]
        assert aq["status"] == "healthy"
        assert aq["depth"] == 50
        assert aq["ws_subscribers"] == 3

    @pytest.mark.asyncio
    async def test_alert_queue_degraded(self) -> None:
        """알림 큐가 거의 가득 찬 경우 degraded를 반환하는지 검증한다."""
        mock_queue = MagicMock()
        mock_queue.qsize.return_value = 9500  # 95% of maxsize
        mock_queue.maxsize = 10000

        mock_dispatcher               = MagicMock()
        mock_dispatcher._queue         = mock_queue
        mock_dispatcher._ws_subscribers = set()

        checker = HealthChecker(dispatcher=mock_dispatcher)
        result  = await checker.check_all()

        assert result["components"]["alert_queue"]["status"] == "degraded"
        assert result["overall_status"] == "degraded"

    @pytest.mark.asyncio
    async def test_version_and_uptime(self) -> None:
        """버전과 업타임 정보가 포함되는지 검증한다."""
        import netwatcher

        checker = HealthChecker()
        result  = await checker.check_all()

        assert result["version"] == netwatcher.__version__
        assert isinstance(result["uptime_seconds"], float)
        assert result["uptime_seconds"] >= 0

    @pytest.mark.asyncio
    async def test_redis_healthy(self) -> None:
        """Redis가 정상 응답할 때 healthy를 반환하는지 검증한다."""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)

        checker = HealthChecker(redis_client=mock_redis)
        result  = await checker.check_all()

        assert result["components"]["redis"]["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_redis_unhealthy(self) -> None:
        """Redis 연결 실패 시 unhealthy를 반환하는지 검증한다."""
        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(side_effect=ConnectionError("refused"))

        checker = HealthChecker(redis_client=mock_redis)
        result  = await checker.check_all()

        assert result["components"]["redis"]["status"] == "unhealthy"
