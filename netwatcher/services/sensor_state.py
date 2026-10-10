"""분리 센서의 실행 소유권과 관측 상태를 갱신한다."""

import asyncio
import time
import logging
from uuid import uuid4

from netwatcher.storage.sensor_state import SensorLeaseLost, StoredSensorObservation, _identity, _lease

logger = logging.getLogger("netwatcher.services.sensor_state")


class SensorObservationReader:
    """센서 임대를 변경하지 않고 독립 콘솔의 관측 캐시를 갱신한다."""

    def __init__(self, observation, *, interval=2, timeout_seconds=2):
        if not isinstance(observation, StoredSensorObservation):
            raise ValueError("DB 센서 관측 제공자가 필요합니다")
        if (isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 1 <= interval <= 10
                or isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not .1 <= timeout_seconds <= 2):
            raise ValueError("관측 조회 간격과 제한 시간이 유효하지 않습니다")
        self.observation = observation
        self.interval, self.timeout_seconds = interval, timeout_seconds
        self._task = None
        self._error = None
        self._lifecycle_lock = asyncio.Lock()
        self._stopping = True

    async def _refresh_once(self):
        try:
            async with asyncio.timeout(self.timeout_seconds):
                await self.observation.refresh()
        except Exception as exc:
            reason = type(exc).__name__
            if reason != self._error:
                logger.warning("Sensor observation read failed (%s)", reason)
            self._error = reason
        else:
            if self._error is not None:
                logger.info("Sensor observation read recovered")
            self._error = None

    async def _run(self):
        while not self._stopping:
            await asyncio.sleep(self.interval)
            if self._stopping:
                return
            await self._refresh_once()

    async def start(self):
        async with self._lifecycle_lock:
            if self._task is not None and not self._task.done():
                return
            await self._refresh_once()
            self._stopping = False
            self._task = asyncio.create_task(self._run())

    async def stop(self):
        async with self._lifecycle_lock:
            self._stopping = True
            try:
                if self._task is not None:
                    caller = asyncio.current_task()
                    cancel_count = caller.cancelling()
                    self._task.cancel()
                    try:
                        await self._task
                    except asyncio.CancelledError:
                        if caller.cancelling() > cancel_count:
                            raise
            finally:
                self._task = None
                self.observation.invalidate()

    def status(self):
        running = self._task is not None and not self._task.done() and not self._stopping
        current = self.observation.snapshot()
        return {"status": "unhealthy" if not running or self._error is not None else
                "healthy" if current["sensor_heartbeat"]["confirmed"] and current["state"] in ("observed", "partial")
                else "degraded", "sensor_id": self.observation.sensor_id, "reason": self._error}


class SensorStatePublisher:
    def __init__(self, repository, sensor_id, source, on_lost, *, interval=5, lease_seconds=30):
        self.owner = uuid4()
        _identity(sensor_id, self.owner)
        _lease(lease_seconds)
        if (isinstance(interval, bool) or not isinstance(interval, (int, float))
                or not 1 <= interval <= 10 or lease_seconds < interval * 3):
            raise ValueError("센서 heartbeat 간격과 실행 소유권 유효기간이 유효하지 않습니다")
        if not callable(source) or not callable(on_lost):
            raise ValueError("센서 관측 제공자와 입력 중단 처리가 필요합니다")
        self.repository, self.sensor_id = repository, sensor_id
        self.source, self.on_lost = source, on_lost
        self.interval, self.lease_seconds = interval, lease_seconds
        self.lost = False
        self._attempted = False
        self._task = None
        self.last_publish_ms: float | None = None

    async def start(self):
        if self._task is not None and not self._task.done():
            return
        if self.lost:
            raise SensorLeaseLost("소유권을 잃은 센서 실행은 다시 사용할 수 없습니다")
        self._attempted = True
        async with asyncio.timeout(2):
            await self.repository.claim(self.sensor_id, self.owner, lease_seconds=self.lease_seconds)
        await self.publish_once()
        self._task = asyncio.create_task(self._run())

    async def publish_once(self):
        if self.lost:
            raise SensorLeaseLost("센서 실행 소유권을 확인할 수 없습니다")
        try:
            snapshot = self.source()
            started = time.monotonic()
            async with asyncio.timeout(2):
                await self.repository.publish(self.sensor_id, self.owner, snapshot, lease_seconds=self.lease_seconds)
            self.last_publish_ms = (time.monotonic() - started) * 1000
        except Exception as exc:
            self.lost = True
            logger.error("Sensor lease unconfirmed; stopping input (%s)", type(exc).__name__)
            self.on_lost()
            raise SensorLeaseLost("센서 상태를 확정하지 못해 입력 중단을 요청했습니다") from None

    async def _run(self):
        while not self.lost:
            await asyncio.sleep(self.interval)
            try:
                await self.publish_once()
            except SensorLeaseLost:
                return

    async def stop(self):
        if self._task is not None:
            caller = asyncio.current_task()
            cancel_count = caller.cancelling()
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                if caller.cancelling() > cancel_count:
                    raise
            finally:
                self._task = None
        if self._attempted:
            async with asyncio.timeout(2):
                await self.repository.release(self.sensor_id, self.owner)
