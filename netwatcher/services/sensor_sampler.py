"""센서 운영 표본 기록.

이벤트 루프 지연, 리스 갱신 소요, cgroup CPU 스로틀링·메모리 압력을 일정 간격으로 저장한다.
센서가 주기적으로 리스를 잃는 원인을 시각별로 대조하고, 관측 탭에 보여 주는 데 쓴다.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("netwatcher.services.sensor_sampler")

CGROUP_ROOT = Path("/sys/fs/cgroup")


def _cgroup_dir() -> Path | None:
    """cgroup v2에서 이 프로세스가 속한 디렉터리. 없으면 None."""
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            hierarchy, _, path = line.split(":", 2)
            if hierarchy == "0":
                directory = CGROUP_ROOT / path.lstrip("/")
                return directory if directory.is_dir() else None
    except (OSError, ValueError):
        return None
    return None


def _keyed(path: Path) -> dict[str, int]:
    values = {}
    try:
        for line in path.read_text().splitlines():
            key, _, value = line.partition(" ")
            if value.strip().isdigit():
                values[key] = int(value)
    except OSError:
        pass
    return values


def read_cgroup(directory: Path | None) -> dict[str, int | None]:
    """읽지 못한 값은 0이 아니라 None으로 둔다."""
    if directory is None:
        return dict.fromkeys(("cpu_usage_usec", "cpu_throttled_usec", "memory_current", "memory_high_events"))
    cpu = _keyed(directory / "cpu.stat")
    events = _keyed(directory / "memory.events")
    try:
        memory = int((directory / "memory.current").read_text().strip())
    except (OSError, ValueError):
        memory = None
    return {"cpu_usage_usec": cpu.get("usage_usec"), "cpu_throttled_usec": cpu.get("throttled_usec"),
            "memory_current": memory, "memory_high_events": events.get("high")}


class SensorSampler:
    def __init__(self, db, sensor_id: str, publisher=None, *, interval: float = 30, retention_days: int = 7):
        if not 5 <= interval <= 300:
            raise ValueError("sensor sample interval must be 5-300 seconds")
        self.db, self.sensor_id, self.publisher = db, sensor_id, publisher
        self.interval, self.retention_days = interval, retention_days
        self.boot_id = uuid.uuid4()
        self.cgroup = _cgroup_dir()
        self.failures = 0
        self._task: asyncio.Task | None = None

    def sample(self, loop_lag_ms: float) -> dict:
        lease = getattr(self.publisher, "last_publish_ms", None)
        return {"sensor_id": self.sensor_id, "boot_id": self.boot_id, "sampled_at": datetime.now(timezone.utc),
                "loop_lag_ms": loop_lag_ms, "lease_publish_ms": lease, **read_cgroup(self.cgroup)}

    async def store(self, row: dict) -> None:
        await self.db.pool.execute(
            """INSERT INTO sensor_samples(sensor_id, boot_id, sampled_at, loop_lag_ms, lease_publish_ms,
                   cpu_usage_usec, cpu_throttled_usec, memory_current, memory_high_events)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING""",
            row["sensor_id"], row["boot_id"], row["sampled_at"], row["loop_lag_ms"], row["lease_publish_ms"],
            row["cpu_usage_usec"], row["cpu_throttled_usec"], row["memory_current"], row["memory_high_events"])

    async def prune(self) -> None:
        await self.db.pool.execute(
            "DELETE FROM sensor_samples WHERE sensor_id = $1 AND sampled_at < clock_timestamp() - make_interval(days => $2)",
            self.sensor_id, self.retention_days)

    async def _run(self) -> None:
        rounds = 0
        while True:
            started = time.monotonic()
            await asyncio.sleep(self.interval)
            # 잠든 시간이 요청보다 길어진 만큼이 이벤트 루프가 밀린 시간이다.
            lag = max(0.0, (time.monotonic() - started - self.interval) * 1000)
            try:
                async with asyncio.timeout(2):
                    await self.store(self.sample(lag))
                    rounds += 1
                    if rounds % 120 == 1:
                        await self.prune()
                self.failures = 0
            except Exception as exc:
                # 표본은 진단 보조 자료라 실패해도 센서를 멈추지 않는다. 연속 실패 수는 남긴다.
                self.failures += 1
                if self.failures in (1, 10) or self.failures % 100 == 0:
                    logger.warning("Sensor sample not stored (%s), consecutive failures=%d", type(exc).__name__, self.failures)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is None:
            return
        caller = asyncio.current_task()
        cancel_count = caller.cancelling() if caller else 0
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            # 표본 작업의 취소만 삼키고, 정지를 부른 쪽이 취소된 경우는 다시 올린다.
            if caller is not None and caller.cancelling() > cancel_count:
                raise
        finally:
            self._task = None
