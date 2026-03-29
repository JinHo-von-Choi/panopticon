"""비동기 Redis 클라이언트 래퍼 -- 연결 실패 시 우아한 저하."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("netwatcher.cache.redis_client")


class RedisClient:
    """비동기 Redis 클라이언트. Redis 미설치 또는 연결 불가 시 자동으로 비활성 모드 전환.

    모든 공개 메서드는 Redis 미사용 시 None/False/0을 반환하며 예외를 발생시키지 않는다.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: str = "",
        key_prefix: str = "nw:",
        enabled: bool = False,
    ) -> None:
        self._host       = host
        self._port       = port
        self._db         = db
        self._password   = password
        self._key_prefix = key_prefix
        self._enabled    = enabled
        self._available  = False
        self._pool: Any  = None  # redis.asyncio.ConnectionPool

    @staticmethod
    def _import_aioredis() -> Any:
        """redis.asyncio 모듈을 동적으로 임포트한다. 테스트 시 모킹 포인트."""
        import redis.asyncio as aioredis
        return aioredis

    async def connect(self) -> bool:
        """Redis 연결을 시도한다. 실패 시 False를 반환하고 비활성 모드로 전환."""
        if not self._enabled:
            logger.info("Redis disabled by configuration")
            return False

        try:
            aioredis = self._import_aioredis()
        except ImportError:
            logger.warning("redis[hiredis] package not installed -- Redis caching disabled")
            return False

        try:
            self._pool = aioredis.ConnectionPool(
                host=self._host,
                port=self._port,
                db=self._db,
                password=self._password or None,
                decode_responses=False,
                max_connections=20,
            )
            client = aioredis.Redis(connection_pool=self._pool)
            await client.ping()
            await client.aclose()
            self._available = True
            logger.info("Redis connected: %s:%d db=%d", self._host, self._port, self._db)
            return True
        except Exception:
            logger.warning(
                "Redis connection failed (%s:%d) -- falling back to in-memory",
                self._host, self._port,
            )
            self._available = False
            return False

    async def close(self) -> None:
        """연결 풀을 정리한다."""
        if self._pool is not None:
            try:
                await self._pool.disconnect()
            except Exception:
                pass
            self._pool     = None
            self._available = False

    @property
    def available(self) -> bool:
        """Redis가 사용 가능한지 여부를 반환한다."""
        return self._available

    def _prefixed(self, key: str) -> str:
        """키에 네임스페이스 접두사를 추가한다."""
        return f"{self._key_prefix}{key}"

    def _client(self) -> Any:
        """현재 풀에서 Redis 클라이언트를 생성한다."""
        import redis.asyncio as aioredis
        return aioredis.Redis(connection_pool=self._pool)

    async def get(self, key: str) -> bytes | None:
        """키에 해당하는 값을 조회한다."""
        if not self._available:
            return None
        try:
            client = self._client()
            try:
                return await client.get(self._prefixed(key))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis GET failed for key=%s", key)
            return None

    async def set(self, key: str, value: bytes, ttl: int = 0) -> bool:
        """키-값을 저장한다. ttl > 0이면 만료 시간을 설정한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                if ttl > 0:
                    await client.setex(self._prefixed(key), ttl, value)
                else:
                    await client.set(self._prefixed(key), value)
                return True
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SET failed for key=%s", key)
            return False

    async def setex(self, key: str, ttl: int, value: bytes) -> bool:
        """키-값을 TTL과 함께 저장한다."""
        return await self.set(key, value, ttl=ttl)

    async def delete(self, key: str) -> bool:
        """키를 삭제한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                await client.delete(self._prefixed(key))
                return True
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis DELETE failed for key=%s", key)
            return False

    async def exists(self, key: str) -> bool:
        """키 존재 여부를 확인한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                return bool(await client.exists(self._prefixed(key)))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis EXISTS failed for key=%s", key)
            return False

    async def incr(self, key: str) -> int:
        """키 값을 1 증가시킨다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.incr(self._prefixed(key))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis INCR failed for key=%s", key)
            return 0

    async def expire(self, key: str, ttl: int) -> bool:
        """키에 만료 시간을 설정한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                return bool(await client.expire(self._prefixed(key), ttl))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis EXPIRE failed for key=%s", key)
            return False

    async def pipeline(self) -> Any:
        """파이프라인 객체를 반환한다. MULTI/EXEC 배치 처리용."""
        if not self._available:
            return None
        try:
            client = self._client()
            return client.pipeline(transaction=True)
        except Exception:
            logger.warning("Redis pipeline creation failed")
            return None

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        """정렬된 집합에 멤버를 추가한다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.zadd(self._prefixed(key), mapping)
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis ZADD failed for key=%s", key)
            return 0

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int:
        """점수 범위로 정렬된 집합의 멤버를 제거한다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.zremrangebyscore(self._prefixed(key), min_score, max_score)
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis ZREMRANGEBYSCORE failed for key=%s", key)
            return 0

    async def zcard(self, key: str) -> int:
        """정렬된 집합의 멤버 수를 반환한다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.zcard(self._prefixed(key))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis ZCARD failed for key=%s", key)
            return 0

    async def sadd(self, key: str, *values: str) -> int:
        """집합에 멤버를 추가한다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.sadd(self._prefixed(key), *values)
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SADD failed for key=%s", key)
            return 0

    async def sismember(self, key: str, value: str) -> bool:
        """집합에 멤버가 존재하는지 확인한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                return bool(await client.sismember(self._prefixed(key), value))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SISMEMBER failed for key=%s", key)
            return False

    async def smembers(self, key: str) -> set[bytes]:
        """집합의 모든 멤버를 반환한다."""
        if not self._available:
            return set()
        try:
            client = self._client()
            try:
                return await client.smembers(self._prefixed(key))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SMEMBERS failed for key=%s", key)
            return set()

    async def srem(self, key: str, *values: str) -> int:
        """집합에서 멤버를 제거한다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.srem(self._prefixed(key), *values)
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SREM failed for key=%s", key)
            return 0

    async def set_nx(self, key: str, value: bytes, ttl: int) -> bool:
        """SET key value NX EX ttl -- 키가 없을 때만 설정한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                result = await client.set(self._prefixed(key), value, nx=True, ex=ttl)
                return result is not None
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SET NX failed for key=%s", key)
            return False

    async def set_xx(self, key: str, value: bytes, ttl: int) -> bool:
        """SET key value XX EX ttl -- 키가 이미 있을 때만 설정한다."""
        if not self._available:
            return False
        try:
            client = self._client()
            try:
                result = await client.set(self._prefixed(key), value, xx=True, ex=ttl)
                return result is not None
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis SET XX failed for key=%s", key)
            return False

    async def hset(self, key: str, mapping: dict[str, str]) -> int:
        """해시에 여러 필드를 설정한다."""
        if not self._available:
            return 0
        try:
            client = self._client()
            try:
                return await client.hset(self._prefixed(key), mapping=mapping)
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis HSET failed for key=%s", key)
            return 0

    async def hgetall(self, key: str) -> dict[bytes, bytes]:
        """해시의 모든 필드와 값을 반환한다."""
        if not self._available:
            return {}
        try:
            client = self._client()
            try:
                return await client.hgetall(self._prefixed(key))
            finally:
                await client.aclose()
        except Exception:
            logger.warning("Redis HGETALL failed for key=%s", key)
            return {}
