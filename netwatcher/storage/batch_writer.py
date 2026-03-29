"""이벤트를 버퍼에 축적한 후 일괄 플러시하여 DB 처리량을 높이는 BatchWriter."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netwatcher.storage.repositories import EventRepository

logger = logging.getLogger("netwatcher.storage.batch_writer")


class BatchWriter:
    """이벤트를 메모리 버퍼에 축적하고 batch_size 또는 flush_interval 도달 시 일괄 삽입한다."""

    def __init__(
        self,
        event_repo: EventRepository,
        batch_size: int = 50,
        flush_interval_ms: int = 1000,
    ) -> None:
        """BatchWriter를 초기화한다.

        Args:
            event_repo: 이벤트 삽입에 사용할 EventRepository 인스턴스.
            batch_size: 자동 플러시를 유발하는 버퍼 임계값.
            flush_interval_ms: 주기적 플러시 간격(밀리초).
        """
        self._event_repo  = event_repo
        self._batch_size  = batch_size
        self._flush_interval = flush_interval_ms / 1000.0
        self._buffer: list[dict] = []
        self._lock = asyncio.Lock()
        self._last_flush  = time.monotonic()
        self._flush_task: asyncio.Task | None = None
        self._running = False

    @property
    def pending(self) -> int:
        """현재 버퍼에 대기 중인 이벤트 수를 반환한다."""
        return len(self._buffer)

    async def enqueue(self, event_data: dict) -> None:
        """이벤트를 버퍼에 추가한다. batch_size에 도달하면 즉시 플러시한다."""
        async with self._lock:
            self._buffer.append(event_data)
            if len(self._buffer) >= self._batch_size:
                await self._flush_locked()

    async def flush(self) -> int:
        """버퍼의 모든 이벤트를 DB에 플러시한다. 플러시된 건수를 반환한다."""
        async with self._lock:
            return await self._flush_locked()

    async def _flush_locked(self) -> int:
        """락을 이미 획득한 상태에서 내부 플러시를 수행한다."""
        if not self._buffer:
            self._last_flush = time.monotonic()
            return 0

        batch = self._buffer[:]
        self._buffer.clear()

        try:
            count = await self._event_repo.insert_batch(batch)
            self._last_flush = time.monotonic()
            logger.debug("BatchWriter flushed %d events", count)
            return count
        except Exception:
            logger.exception("BatchWriter flush failed, %d events lost", len(batch))
            self._last_flush = time.monotonic()
            return 0

    async def start(self) -> None:
        """주기적 플러시 태스크를 시작한다."""
        if self._running:
            return
        self._running = True
        self._last_flush = time.monotonic()
        self._flush_task = asyncio.create_task(self._periodic_flush_loop())

    async def stop(self) -> None:
        """잔여 이벤트를 플러시하고 주기적 태스크를 중단한다."""
        self._running = False
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        # 최종 플러시
        await self.flush()

    async def _periodic_flush_loop(self) -> None:
        """flush_interval마다 버퍼를 플러시하는 루프."""
        while self._running:
            try:
                await asyncio.sleep(self._flush_interval)
                elapsed = time.monotonic() - self._last_flush
                if elapsed >= self._flush_interval and self._buffer:
                    await self.flush()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Periodic flush loop error")
