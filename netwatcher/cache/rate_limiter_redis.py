"""Redis 정렬 집합 기반 분산 슬라이딩 윈도우 속도 제한기."""

from __future__ import annotations

import time
import uuid
import logging

from netwatcher.cache.redis_client import RedisClient

logger = logging.getLogger("netwatcher.cache.rate_limiter_redis")


class RateLimiterRedis:
    """Redis Sorted Set을 사용한 슬라이딩 윈도우 속도 제한기.

    기존 RateLimiter와 동일한 인터페이스(allow, cleanup)를 제공하며,
    분산 환경에서 공유 상태로 동작한다.

    알고리즘:
    - 각 키를 Sorted Set으로 관리 (score = 타임스탬프, member = 고유 ID)
    - allow() 호출 시:
      1. 윈도우 밖의 오래된 항목 제거 (ZREMRANGEBYSCORE)
      2. 현재 카운트 확인 (ZCARD)
      3. 허용 시 새 항목 추가 (ZADD)
    - TTL이 자동으로 만료를 처리하므로 cleanup은 no-op
    """

    def __init__(
        self,
        redis: RedisClient,
        window_seconds: int = 300,
        max_count: int = 5,
    ) -> None:
        self._redis  = redis
        self._window = window_seconds
        self._max    = max_count

    def _key(self, key: str) -> str:
        """속도 제한 키를 생성한다."""
        return f"rl:{key}"

    async def allow(self, key: str) -> bool:
        """이벤트가 허용되면 True를 반환한다. Redis Sorted Set 슬라이딩 윈도우 사용."""
        if not self._redis.available:
            return True  # Redis 미사용 시 항상 허용 (인메모리 폴백에 위임)

        try:
            now    = time.time()
            cutoff = now - self._window
            rkey   = self._key(key)

            # 1. 윈도우 밖 항목 제거
            await self._redis.zremrangebyscore(rkey, 0, cutoff)

            # 2. 현재 윈도우 내 카운트 확인
            count = await self._redis.zcard(rkey)
            if count >= self._max:
                return False

            # 3. 새 항목 추가 (고유 member로 타임스탬프 충돌 방지)
            member = f"{now}:{uuid.uuid4().hex[:8]}"
            await self._redis.zadd(rkey, {member: now})

            # 4. 키 TTL 설정 (윈도우 + 여유)
            await self._redis.expire(rkey, self._window + 60)

            return True
        except Exception:
            logger.warning("Redis rate limiter failed for key=%s, allowing", key)
            return True  # 실패 시 허용 (가용성 우선)

    def cleanup(self) -> None:
        """No-op. Redis TTL이 만료를 자동 처리한다."""
