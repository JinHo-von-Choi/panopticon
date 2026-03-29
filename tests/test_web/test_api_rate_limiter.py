"""APIRateLimiter 테스트."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.web.api_rate_limiter import APIRateLimiter


class TestInMemoryRateLimiter:
    """인메모리 폴백 테스트."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=5, burst=0)
        for _ in range(5):
            assert await limiter.check("user1") is True

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=3, burst=0)
        for _ in range(3):
            assert await limiter.check("user1") is True
        assert await limiter.check("user1") is False

    @pytest.mark.asyncio
    async def test_burst_adds_to_limit(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=3, burst=2)
        # 3 + 2 = 5 total allowed
        for _ in range(5):
            assert await limiter.check("user1") is True
        assert await limiter.check("user1") is False

    @pytest.mark.asyncio
    async def test_different_keys_independent(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=2, burst=0)
        assert await limiter.check("user1") is True
        assert await limiter.check("user1") is True
        assert await limiter.check("user1") is False
        # user2는 별도 버킷
        assert await limiter.check("user2") is True

    @pytest.mark.asyncio
    async def test_expired_entries_cleared(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=2, burst=0)
        # 수동으로 오래된 타임스탬프 삽입
        import time
        old_ts = time.time() - 120  # 2분 전
        limiter._buckets["user1"] = [old_ts, old_ts]
        # 오래된 항목은 만료되어 새 요청이 허용되어야 함
        assert await limiter.check("user1") is True


class TestRedisRateLimiter:
    """Redis 기반 속도 제한 테스트."""

    @pytest.mark.asyncio
    async def test_redis_allows_within_limit(self):
        mock_redis = MagicMock()
        mock_pipe  = MagicMock()
        mock_pipe.zremrangebyscore = MagicMock(return_value=mock_pipe)
        mock_pipe.zcard            = MagicMock(return_value=mock_pipe)
        mock_pipe.zadd             = MagicMock(return_value=mock_pipe)
        mock_pipe.expire           = MagicMock(return_value=mock_pipe)
        mock_pipe.execute          = AsyncMock(return_value=[0, 2, True, True])
        mock_redis.pipeline        = MagicMock(return_value=mock_pipe)

        limiter = APIRateLimiter(redis_client=mock_redis, requests_per_minute=60, burst=10)
        assert await limiter.check("user1") is True

    @pytest.mark.asyncio
    async def test_redis_blocks_over_limit(self):
        mock_redis = MagicMock()
        mock_pipe  = MagicMock()
        mock_pipe.zremrangebyscore = MagicMock(return_value=mock_pipe)
        mock_pipe.zcard            = MagicMock(return_value=mock_pipe)
        mock_pipe.zadd             = MagicMock(return_value=mock_pipe)
        mock_pipe.expire           = MagicMock(return_value=mock_pipe)
        # count=70 > 60+10=70 경계값
        mock_pipe.execute = AsyncMock(return_value=[0, 70, True, True])
        mock_redis.pipeline = MagicMock(return_value=mock_pipe)

        limiter = APIRateLimiter(redis_client=mock_redis, requests_per_minute=60, burst=10)
        assert await limiter.check("user1") is False

    @pytest.mark.asyncio
    async def test_redis_failure_allows_request(self):
        """Redis 장애 시 요청을 허용한다 (graceful degradation)."""
        mock_redis = MagicMock()
        mock_pipe  = MagicMock()
        mock_pipe.zremrangebyscore = MagicMock(return_value=mock_pipe)
        mock_pipe.zcard            = MagicMock(return_value=mock_pipe)
        mock_pipe.zadd             = MagicMock(return_value=mock_pipe)
        mock_pipe.expire           = MagicMock(return_value=mock_pipe)
        mock_pipe.execute          = AsyncMock(side_effect=ConnectionError("Redis down"))
        mock_redis.pipeline        = MagicMock(return_value=mock_pipe)

        limiter = APIRateLimiter(redis_client=mock_redis, requests_per_minute=60, burst=10)
        assert await limiter.check("user1") is True


class TestRateLimiterDependency:
    """FastAPI 의존성 통합 테스트."""

    @pytest.mark.asyncio
    async def test_dependency_allows_request(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=60, burst=10)
        app     = FastAPI()
        dep     = limiter.as_dependency()

        @app.get("/test", dependencies=[pytest.importorskip("fastapi").Depends(dep)])
        async def test_endpoint():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_dependency_returns_429(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=2, burst=0)
        app     = FastAPI()
        dep     = limiter.as_dependency()

        @app.get("/test", dependencies=[pytest.importorskip("fastapi").Depends(dep)])
        async def test_endpoint():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 첫 2회는 성공
            for _ in range(2):
                resp = await client.get("/test")
                assert resp.status_code == 200
            # 3번째는 429
            resp = await client.get("/test")
            assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_dependency_uses_token_key(self):
        limiter = APIRateLimiter(redis_client=None, requests_per_minute=1, burst=0)
        app     = FastAPI()
        dep     = limiter.as_dependency()

        @app.get("/test", dependencies=[pytest.importorskip("fastapi").Depends(dep)])
        async def test_endpoint():
            return {"ok": True}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 토큰 A: 1회 허용
            resp = await client.get("/test", headers={"Authorization": "Bearer tokenAAA"})
            assert resp.status_code == 200
            # 토큰 A: 초과
            resp = await client.get("/test", headers={"Authorization": "Bearer tokenAAA"})
            assert resp.status_code == 429
            # 토큰 B: 별도 버킷이므로 허용
            resp = await client.get("/test", headers={"Authorization": "Bearer tokenBBB"})
            assert resp.status_code == 200
