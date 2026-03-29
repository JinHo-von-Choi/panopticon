"""RedisClient 단위 테스트 -- Redis 서버 불필요 (모킹)."""

from __future__ import annotations

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from netwatcher.cache.redis_client import RedisClient


@pytest.fixture
def client() -> RedisClient:
    """비활성 상태의 RedisClient를 생성한다."""
    return RedisClient(host="localhost", port=6379, enabled=False)


@pytest.fixture
def enabled_client() -> RedisClient:
    """활성화 설정의 RedisClient를 생성한다."""
    return RedisClient(host="localhost", port=6379, enabled=True, key_prefix="test:")


class TestDisabledClient:
    """Redis 비활성 상태에서의 우아한 저하 테스트."""

    @pytest.mark.asyncio
    async def test_connect_disabled_returns_false(self, client: RedisClient) -> None:
        result = await client.connect()
        assert result is False
        assert client.available is False

    @pytest.mark.asyncio
    async def test_get_returns_none_when_unavailable(self, client: RedisClient) -> None:
        result = await client.get("some_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_returns_false_when_unavailable(self, client: RedisClient) -> None:
        result = await client.set("key", b"value")
        assert result is False

    @pytest.mark.asyncio
    async def test_delete_returns_false_when_unavailable(self, client: RedisClient) -> None:
        result = await client.delete("key")
        assert result is False

    @pytest.mark.asyncio
    async def test_exists_returns_false_when_unavailable(self, client: RedisClient) -> None:
        result = await client.exists("key")
        assert result is False

    @pytest.mark.asyncio
    async def test_incr_returns_zero_when_unavailable(self, client: RedisClient) -> None:
        result = await client.incr("key")
        assert result == 0

    @pytest.mark.asyncio
    async def test_expire_returns_false_when_unavailable(self, client: RedisClient) -> None:
        result = await client.expire("key", 60)
        assert result is False

    @pytest.mark.asyncio
    async def test_setex_returns_false_when_unavailable(self, client: RedisClient) -> None:
        result = await client.setex("key", 60, b"value")
        assert result is False

    @pytest.mark.asyncio
    async def test_zadd_returns_zero_when_unavailable(self, client: RedisClient) -> None:
        result = await client.zadd("key", {"member": 1.0})
        assert result == 0

    @pytest.mark.asyncio
    async def test_zcard_returns_zero_when_unavailable(self, client: RedisClient) -> None:
        result = await client.zcard("key")
        assert result == 0

    @pytest.mark.asyncio
    async def test_sadd_returns_zero_when_unavailable(self, client: RedisClient) -> None:
        result = await client.sadd("key", "val1")
        assert result == 0

    @pytest.mark.asyncio
    async def test_sismember_returns_false_when_unavailable(self, client: RedisClient) -> None:
        result = await client.sismember("key", "val")
        assert result is False

    @pytest.mark.asyncio
    async def test_smembers_returns_empty_when_unavailable(self, client: RedisClient) -> None:
        result = await client.smembers("key")
        assert result == set()

    @pytest.mark.asyncio
    async def test_pipeline_returns_none_when_unavailable(self, client: RedisClient) -> None:
        result = await client.pipeline()
        assert result is None

    @pytest.mark.asyncio
    async def test_close_noop_when_no_pool(self, client: RedisClient) -> None:
        await client.close()  # should not raise


class TestKeyPrefixing:
    """키 접두사 테스트."""

    def test_prefixed_key(self) -> None:
        client = RedisClient(key_prefix="myapp:")
        assert client._prefixed("test") == "myapp:test"

    def test_default_prefix(self) -> None:
        client = RedisClient()
        assert client._prefixed("k") == "nw:k"


class TestConnectionFlow:
    """connect/close 흐름 테스트 (모킹)."""

    @pytest.mark.asyncio
    async def test_connect_success(self, enabled_client: RedisClient) -> None:
        mock_pool     = MagicMock()
        mock_instance = AsyncMock()
        mock_instance.ping   = AsyncMock()
        mock_instance.aclose = AsyncMock()

        mock_aioredis = MagicMock()
        mock_aioredis.ConnectionPool.return_value = mock_pool
        mock_aioredis.Redis.return_value = mock_instance

        with patch("netwatcher.cache.redis_client.RedisClient._import_aioredis", return_value=mock_aioredis):
            result = await enabled_client.connect()
            assert result is True
            assert enabled_client.available is True

    @pytest.mark.asyncio
    async def test_connect_import_error(self, enabled_client: RedisClient) -> None:
        """redis 패키지 미설치 시 False 반환."""
        with patch("netwatcher.cache.redis_client.RedisClient._import_aioredis", side_effect=ImportError("no redis")):
            result = await enabled_client.connect()
            assert result is False
            assert enabled_client.available is False

    @pytest.mark.asyncio
    async def test_connect_failure_graceful(self, enabled_client: RedisClient) -> None:
        """연결 실패 시 False 반환."""
        mock_inst       = AsyncMock()
        mock_inst.ping  = AsyncMock(side_effect=ConnectionError("refused"))
        mock_inst.aclose = AsyncMock()

        mock_aioredis = MagicMock()
        mock_aioredis.ConnectionPool.return_value = MagicMock()
        mock_aioredis.Redis.return_value = mock_inst

        with patch("netwatcher.cache.redis_client.RedisClient._import_aioredis", return_value=mock_aioredis):
            result = await enabled_client.connect()
            assert result is False
            assert enabled_client.available is False


def _make_mock_redis_instance() -> AsyncMock:
    """모킹된 Redis 인스턴스를 생성한다."""
    inst        = AsyncMock()
    inst.get    = AsyncMock(return_value=b"hello")
    inst.set    = AsyncMock(return_value=True)
    inst.setex  = AsyncMock(return_value=True)
    inst.delete = AsyncMock(return_value=1)
    inst.exists = AsyncMock(return_value=1)
    inst.incr   = AsyncMock(return_value=5)
    inst.expire = AsyncMock(return_value=True)
    inst.zadd   = AsyncMock(return_value=1)
    inst.zremrangebyscore = AsyncMock(return_value=0)
    inst.zcard  = AsyncMock(return_value=3)
    inst.sadd   = AsyncMock(return_value=1)
    inst.sismember = AsyncMock(return_value=True)
    inst.smembers  = AsyncMock(return_value={b"a", b"b"})
    inst.aclose    = AsyncMock()
    inst.pipeline  = MagicMock()
    return inst


class TestOperationsWithMockedRedis:
    """Redis 사용 가능 상태에서의 작업 테스트 (모킹)."""

    @pytest_asyncio.fixture
    async def mock_client(self) -> RedisClient:
        """available=True 상태의 모킹된 RedisClient."""
        client = RedisClient(host="localhost", port=6379, enabled=True, key_prefix="t:")
        client._available = True
        client._pool      = MagicMock()

        mock_inst = _make_mock_redis_instance()
        client._client = MagicMock(return_value=mock_inst)  # type: ignore[method-assign]
        yield client

    @pytest.mark.asyncio
    async def test_get(self, mock_client: RedisClient) -> None:
        result = await mock_client.get("foo")
        assert result == b"hello"

    @pytest.mark.asyncio
    async def test_set(self, mock_client: RedisClient) -> None:
        result = await mock_client.set("foo", b"bar")
        assert result is True

    @pytest.mark.asyncio
    async def test_set_with_ttl(self, mock_client: RedisClient) -> None:
        result = await mock_client.set("foo", b"bar", ttl=60)
        assert result is True

    @pytest.mark.asyncio
    async def test_setex(self, mock_client: RedisClient) -> None:
        result = await mock_client.setex("foo", 60, b"bar")
        assert result is True

    @pytest.mark.asyncio
    async def test_delete(self, mock_client: RedisClient) -> None:
        result = await mock_client.delete("foo")
        assert result is True

    @pytest.mark.asyncio
    async def test_exists(self, mock_client: RedisClient) -> None:
        result = await mock_client.exists("foo")
        assert result is True

    @pytest.mark.asyncio
    async def test_incr(self, mock_client: RedisClient) -> None:
        result = await mock_client.incr("counter")
        assert result == 5

    @pytest.mark.asyncio
    async def test_expire(self, mock_client: RedisClient) -> None:
        result = await mock_client.expire("foo", 120)
        assert result is True

    @pytest.mark.asyncio
    async def test_zadd(self, mock_client: RedisClient) -> None:
        result = await mock_client.zadd("zkey", {"m": 1.0})
        assert result == 1

    @pytest.mark.asyncio
    async def test_zcard(self, mock_client: RedisClient) -> None:
        result = await mock_client.zcard("zkey")
        assert result == 3

    @pytest.mark.asyncio
    async def test_sadd(self, mock_client: RedisClient) -> None:
        result = await mock_client.sadd("skey", "v1")
        assert result == 1

    @pytest.mark.asyncio
    async def test_sismember(self, mock_client: RedisClient) -> None:
        result = await mock_client.sismember("skey", "v1")
        assert result is True

    @pytest.mark.asyncio
    async def test_smembers(self, mock_client: RedisClient) -> None:
        result = await mock_client.smembers("skey")
        assert result == {b"a", b"b"}


class TestGracefulExceptionHandling:
    """Redis 오류 시 예외 전파 없이 기본값 반환 테스트."""

    @pytest_asyncio.fixture
    async def failing_client(self) -> RedisClient:
        """모든 작업이 예외를 발생시키는 모킹된 클라이언트."""
        client = RedisClient(host="localhost", port=6379, enabled=True, key_prefix="f:")
        client._available = True
        client._pool      = MagicMock()

        mock_inst        = AsyncMock()
        mock_inst.get    = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.set    = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.setex  = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.delete = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.exists = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.incr   = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.expire = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.zadd   = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.zremrangebyscore = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.zcard  = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.sadd   = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.sismember = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.smembers  = AsyncMock(side_effect=ConnectionError("broken"))
        mock_inst.aclose    = AsyncMock()

        client._client = MagicMock(return_value=mock_inst)  # type: ignore[method-assign]
        yield client

    @pytest.mark.asyncio
    async def test_get_exception_returns_none(self, failing_client: RedisClient) -> None:
        assert await failing_client.get("k") is None

    @pytest.mark.asyncio
    async def test_set_exception_returns_false(self, failing_client: RedisClient) -> None:
        assert await failing_client.set("k", b"v") is False

    @pytest.mark.asyncio
    async def test_delete_exception_returns_false(self, failing_client: RedisClient) -> None:
        assert await failing_client.delete("k") is False

    @pytest.mark.asyncio
    async def test_exists_exception_returns_false(self, failing_client: RedisClient) -> None:
        assert await failing_client.exists("k") is False

    @pytest.mark.asyncio
    async def test_incr_exception_returns_zero(self, failing_client: RedisClient) -> None:
        assert await failing_client.incr("k") == 0

    @pytest.mark.asyncio
    async def test_zadd_exception_returns_zero(self, failing_client: RedisClient) -> None:
        assert await failing_client.zadd("k", {"m": 1.0}) == 0

    @pytest.mark.asyncio
    async def test_zcard_exception_returns_zero(self, failing_client: RedisClient) -> None:
        assert await failing_client.zcard("k") == 0

    @pytest.mark.asyncio
    async def test_sadd_exception_returns_zero(self, failing_client: RedisClient) -> None:
        assert await failing_client.sadd("k", "v") == 0

    @pytest.mark.asyncio
    async def test_sismember_exception_returns_false(self, failing_client: RedisClient) -> None:
        assert await failing_client.sismember("k", "v") is False

    @pytest.mark.asyncio
    async def test_smembers_exception_returns_empty(self, failing_client: RedisClient) -> None:
        assert await failing_client.smembers("k") == set()
