"""엔진 상태를 Redis에 주기적으로 직렬화하여 장애 복구를 지원한다."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from netwatcher.cache.redis_client import RedisClient

if TYPE_CHECKING:
    from netwatcher.detection.base import DetectionEngine

logger = logging.getLogger("netwatcher.cache.engine_state")


class EngineStateManager:
    """탐지 엔진의 상태를 Redis에 JSON으로 직렬화/역직렬화한다.

    보안을 위해 JSON 직렬화만 사용한다.
    엔진은 export_state() / import_state()를 선택적으로 구현하여 상태 영속성을 지원한다.
    """

    def __init__(self, redis: RedisClient, interval_seconds: int = 60) -> None:
        self._redis    = redis
        self._interval = interval_seconds

    @property
    def interval(self) -> int:
        """상태 저장 주기(초)를 반환한다."""
        return self._interval

    def _state_key(self, engine_name: str) -> str:
        """엔진 상태 Redis 키를 생성한다."""
        return f"engine_state:{engine_name}"

    async def save_state(self, engine_name: str, state: dict) -> bool:
        """엔진 상태를 Redis에 JSON으로 저장한다."""
        if not self._redis.available:
            return False

        try:
            data = json.dumps(state, default=str).encode()
            # 상태는 3배 주기 동안 유효 (주기적 갱신 실패 대비)
            ttl = self._interval * 3
            return await self._redis.setex(self._state_key(engine_name), ttl, data)
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Failed to serialize state for engine %s: %s", engine_name, exc,
            )
            return False
        except Exception:
            logger.warning("Failed to save state for engine %s", engine_name)
            return False

    async def load_state(self, engine_name: str) -> dict | None:
        """Redis에서 엔진 상태를 로드한다."""
        if not self._redis.available:
            return None

        try:
            data = await self._redis.get(self._state_key(engine_name))
            if data is None:
                return None
            return json.loads(data)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning(
                "Failed to deserialize state for engine %s: %s", engine_name, exc,
            )
            return None
        except Exception:
            logger.warning("Failed to load state for engine %s", engine_name)
            return None

    async def save_all(self, engines: list[DetectionEngine]) -> int:
        """export_state()를 구현한 모든 엔진의 상태를 저장한다. 저장된 수를 반환."""
        saved = 0
        for engine in engines:
            state = engine.export_state()
            if state is not None:
                if await self.save_state(engine.name, state):
                    saved += 1
        if saved:
            logger.debug("Saved state for %d engines", saved)
        return saved

    async def load_all(self, engines: list[DetectionEngine]) -> int:
        """import_state()를 구현한 모든 엔진의 상태를 복원한다. 복원된 수를 반환."""
        loaded = 0
        for engine in engines:
            # export_state가 None을 반환하면 이 엔진은 상태 관리 미지원
            if engine.export_state() is None:
                continue

            state = await self.load_state(engine.name)
            if state is not None:
                try:
                    engine.import_state(state)
                    loaded += 1
                    logger.info("Restored state for engine: %s", engine.name)
                except Exception:
                    logger.warning(
                        "Failed to import state for engine: %s", engine.name,
                    )
        return loaded
