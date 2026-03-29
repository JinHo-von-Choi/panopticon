"""Redis 기반 위협 인텔리전스 피드 캐시."""

from __future__ import annotations

import json
import logging

from netwatcher.cache.redis_client import RedisClient

logger = logging.getLogger("netwatcher.cache.feed_cache")


class FeedCache:
    """위협 인텔리전스 피드를 Redis에 TTL과 함께 캐싱한다.

    피드 데이터는 Redis Set으로 저장하여 O(1) 멤버십 조회를 지원한다.
    피드 항목 목록은 JSON 직렬화된 리스트로 별도 키에 저장한다.
    """

    def __init__(self, redis: RedisClient, default_ttl: int = 21600) -> None:
        """기본 TTL은 6시간(21600초)."""
        self._redis      = redis
        self._default_ttl = default_ttl

    def _feed_key(self, feed_name: str, feed_type: str) -> str:
        """피드별 Redis 키를 생성한다."""
        safe_name = feed_name.replace(" ", "_").lower()
        return f"feed:{feed_type}:{safe_name}"

    def _type_index_key(self, feed_type: str) -> str:
        """피드 타입별 통합 인덱스 키를 생성한다."""
        return f"feed_index:{feed_type}"

    async def set_feed(self, feed_name: str, feed_type: str, entries: set[str]) -> bool:
        """피드 항목을 Redis Set으로 저장한다."""
        if not self._redis.available or not entries:
            return False

        try:
            feed_key  = self._feed_key(feed_name, feed_type)
            index_key = self._type_index_key(feed_type)

            # 기존 피드 데이터 삭제 후 새로 저장
            await self._redis.delete(feed_key)

            # Set에 항목 추가
            await self._redis.sadd(feed_key, *entries)
            await self._redis.expire(feed_key, self._default_ttl)

            # 타입별 통합 인덱스에도 추가
            await self._redis.sadd(index_key, *entries)
            await self._redis.expire(index_key, self._default_ttl)

            # 항목 목록을 JSON으로도 저장 (복원용)
            list_key = f"{feed_key}:list"
            data     = json.dumps(sorted(entries)).encode()
            await self._redis.setex(list_key, self._default_ttl, data)

            logger.debug(
                "Feed cached: %s (%s) -- %d entries, TTL=%ds",
                feed_name, feed_type, len(entries), self._default_ttl,
            )
            return True
        except Exception:
            logger.warning("Failed to cache feed: %s (%s)", feed_name, feed_type)
            return False

    async def get_feed(self, feed_name: str, feed_type: str) -> set[str] | None:
        """캐싱된 피드 항목을 반환한다. 캐시 미스 시 None."""
        if not self._redis.available:
            return None

        try:
            list_key = f"{self._feed_key(feed_name, feed_type)}:list"
            data     = await self._redis.get(list_key)
            if data is None:
                return None

            entries = json.loads(data)
            return set(entries)
        except Exception:
            logger.warning("Failed to read cached feed: %s (%s)", feed_name, feed_type)
            return None

    async def is_in_feed(self, feed_type: str, value: str) -> bool:
        """값이 해당 타입의 통합 인덱스에 존재하는지 O(1)으로 확인한다."""
        if not self._redis.available:
            return False

        try:
            index_key = self._type_index_key(feed_type)
            return await self._redis.sismember(index_key, value)
        except Exception:
            logger.warning("Failed to check feed membership: %s in %s", value, feed_type)
            return False
