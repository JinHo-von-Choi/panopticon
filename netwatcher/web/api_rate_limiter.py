"""API 요청 속도 제한기.

Redis 사용 가능 시 Redis 기반 슬라이딩 윈도우, 불가능 시 인메모리 폴백.
FastAPI 의존성으로 주입 가능하다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from fastapi import Depends, HTTPException, Request

logger = logging.getLogger("netwatcher.web.api_rate_limiter")


class APIRateLimiter:
    """토큰 버킷 + 슬라이딩 윈도우 방식의 API 속도 제한기.

    Args:
        redis_client: redis.asyncio.Redis 인스턴스. None이면 인메모리 폴백.
        requests_per_minute: 분당 최대 요청 수.
        burst: 순간 버스트 허용량 (requests_per_minute에 추가).
    """

    def __init__(
        self,
        redis_client: Any = None,
        requests_per_minute: int = 60,
        burst: int = 10,
    ) -> None:
        self._redis             = redis_client
        self._rpm               = max(requests_per_minute, 1)
        self._burst             = max(burst, 0)
        self._max_per_window    = self._rpm + self._burst
        self._window_seconds    = 60

        # 인메모리 폴백: key -> list[timestamp]
        self._buckets: dict[str, list[float]] = defaultdict(list)

    async def check(self, key: str) -> bool:
        """요청 허용 여부를 반환한다. True = 허용, False = 거부."""
        if self._redis is not None:
            return await self._check_redis(key)
        return self._check_memory(key)

    async def _check_redis(self, key: str) -> bool:
        """Redis sorted set 기반 슬라이딩 윈도우."""
        now      = time.time()
        window   = now - self._window_seconds
        rkey     = f"nw:ratelimit:{key}"

        try:
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(rkey, 0, window)
            pipe.zcard(rkey)
            pipe.zadd(rkey, {str(now): now})
            pipe.expire(rkey, self._window_seconds + 1)
            results = await pipe.execute()
            count   = results[1]
            return count < self._max_per_window
        except Exception:
            logger.warning("Redis rate limit check failed; falling back to allow")
            return True

    def _check_memory(self, key: str) -> bool:
        """인메모리 슬라이딩 윈도우."""
        now    = time.time()
        window = now - self._window_seconds

        timestamps = self._buckets[key]
        # 만료된 항목 제거
        self._buckets[key] = [ts for ts in timestamps if ts > window]
        timestamps = self._buckets[key]

        if len(timestamps) >= self._max_per_window:
            return False
        timestamps.append(now)
        return True

    def as_dependency(self):
        """FastAPI Depends()로 사용할 수 있는 의존성 함수를 반환한다."""
        limiter = self

        async def _rate_limit_dep(request: Request) -> None:
            # 키: 인증된 사용자 또는 클라이언트 IP
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                key = f"token:{auth_header[7:20]}"
            else:
                client_ip = request.client.host if request.client else "unknown"
                key = f"ip:{client_ip}"

            allowed = await limiter.check(key)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Too many requests. Please try again later.",
                )

        return _rate_limit_dep
