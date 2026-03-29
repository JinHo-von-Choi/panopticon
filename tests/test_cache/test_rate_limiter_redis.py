"""RateLimiterRedis 단위 테스트 -- Redis 서버 불필요 (모킹)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from netwatcher.cache.redis_client import RedisClient
from netwatcher.cache.rate_limiter_redis import RateLimiterRedis


@pytest.fixture
def unavailable_redis() -> RedisClient:
    """비활성 RedisClient."""
    client = RedisClient(enabled=False)
    return client


@pytest.fixture
def mock_redis() -> RedisClient:
    """사용 가능 상태의 모킹된 RedisClient."""
    client = RedisClient(enabled=True, key_prefix="t:")
    client._available = True

    # 기본 동작: 빈 sorted set
    client.zremrangebyscore = AsyncMock(return_value=0)
    client.zcard            = AsyncMock(return_value=0)
    client.zadd             = AsyncMock(return_value=1)
    client.expire           = AsyncMock(return_value=True)

    return client


class TestRateLimiterRedisUnavailable:
    """Redis 미사용 시 폴백 테스트."""

    @pytest.mark.asyncio
    async def test_allow_returns_true_when_redis_unavailable(
        self, unavailable_redis: RedisClient,
    ) -> None:
        limiter = RateLimiterRedis(unavailable_redis, window_seconds=60, max_count=3)
        assert await limiter.allow("test_key") is True

    def test_cleanup_noop(self, unavailable_redis: RedisClient) -> None:
        limiter = RateLimiterRedis(unavailable_redis)
        limiter.cleanup()  # no-op, should not raise


class TestRateLimiterRedisAllowed:
    """속도 제한 내 요청 허용 테스트."""

    @pytest.mark.asyncio
    async def test_allow_under_limit(self, mock_redis: RedisClient) -> None:
        limiter = RateLimiterRedis(mock_redis, window_seconds=300, max_count=5)
        mock_redis.zcard = AsyncMock(return_value=2)

        result = await limiter.allow("alert:arp_spoof")
        assert result is True

        mock_redis.zremrangebyscore.assert_called_once()
        mock_redis.zadd.assert_called_once()
        mock_redis.expire.assert_called_once()


class TestRateLimiterRedisBlocked:
    """속도 제한 초과 시 차단 테스트."""

    @pytest.mark.asyncio
    async def test_deny_over_limit(self, mock_redis: RedisClient) -> None:
        limiter = RateLimiterRedis(mock_redis, window_seconds=300, max_count=5)
        mock_redis.zcard = AsyncMock(return_value=5)

        result = await limiter.allow("alert:arp_spoof")
        assert result is False

        # 차단된 경우 zadd가 호출되지 않아야 함
        mock_redis.zadd.assert_not_called()

    @pytest.mark.asyncio
    async def test_deny_exactly_at_limit(self, mock_redis: RedisClient) -> None:
        limiter = RateLimiterRedis(mock_redis, window_seconds=60, max_count=3)
        mock_redis.zcard = AsyncMock(return_value=3)

        result = await limiter.allow("key")
        assert result is False


class TestRateLimiterRedisEdgeCases:
    """엣지 케이스 테스트."""

    @pytest.mark.asyncio
    async def test_first_request_always_allowed(self, mock_redis: RedisClient) -> None:
        limiter = RateLimiterRedis(mock_redis, window_seconds=300, max_count=1)
        mock_redis.zcard = AsyncMock(return_value=0)

        result = await limiter.allow("new_key")
        assert result is True

    @pytest.mark.asyncio
    async def test_exception_allows_through(self, mock_redis: RedisClient) -> None:
        """Redis 오류 시 가용성 우선으로 허용."""
        limiter = RateLimiterRedis(mock_redis, window_seconds=300, max_count=5)
        mock_redis.zremrangebyscore = AsyncMock(side_effect=ConnectionError("broken"))

        result = await limiter.allow("key")
        assert result is True  # 실패 시 허용
