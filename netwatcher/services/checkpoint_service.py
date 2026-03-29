"""주기적 엔진 상태 체크포인트 서비스."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netwatcher.cache.engine_state import EngineStateManager
    from netwatcher.detection.registry import EngineRegistry

logger = logging.getLogger("netwatcher.services.checkpoint_service")


class CheckpointService:
    """엔진 상태를 주기적으로 Redis에 저장하고, 시작 시 복원한다.

    EngineStateManager의 save_all/load_all을 래핑하여
    비동기 루프 기반 자동 체크포인트를 제공한다.
    """

    def __init__(
        self,
        registry: EngineRegistry,
        state_manager: EngineStateManager,
        interval_seconds: int = 60,
    ) -> None:
        self._registry      = registry
        self._state_manager = state_manager
        self._interval       = interval_seconds
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """기존 상태를 복원한 후 주기적 저장 태스크를 시작한다."""
        loaded = await self._state_manager.load_all(self._registry.engines)
        if loaded:
            logger.info("Restored checkpoint state for %d engines", loaded)

        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """마지막 체크포인트를 저장한 후 태스크를 종료한다."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        await self.save_now()

    async def _loop(self) -> None:
        """interval_seconds마다 전체 엔진 상태를 저장한다."""
        while True:
            await asyncio.sleep(self._interval)
            try:
                saved = await self._state_manager.save_all(self._registry.engines)
                if saved:
                    logger.debug("Checkpoint saved for %d engines", saved)
            except Exception:
                logger.exception("Checkpoint save failed")

    async def save_now(self) -> int:
        """즉시 체크포인트를 저장한다. 저장된 엔진 수를 반환한다."""
        try:
            saved = await self._state_manager.save_all(self._registry.engines)
            if saved:
                logger.info("Immediate checkpoint saved for %d engines", saved)
            return saved
        except Exception:
            logger.exception("Immediate checkpoint save failed")
            return 0
