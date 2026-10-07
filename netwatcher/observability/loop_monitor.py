"""이벤트 루프 스케줄링 지연 계측."""

from __future__ import annotations

import asyncio
import math

from netwatcher.web.metrics import event_loop_lag


class LoopMonitor:
    def __init__(self, interval_seconds: float = 0.1) -> None:
        if not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError("interval_seconds must be finite and positive")
        self._interval = interval_seconds
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())
            # 첫 기한을 잡은 뒤 반환하여 직후 발생하는 블로킹도 측정한다.
            await asyncio.sleep(0)

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            deadline = loop.time() + self._interval
            await asyncio.sleep(self._interval)
            event_loop_lag.observe(max(0.0, loop.time() - deadline))
