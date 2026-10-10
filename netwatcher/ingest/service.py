"""복수의 EVE 파일 수집 작업을 시작하고 정상 종료한다."""

import asyncio
import logging

from netwatcher.ingest.assets import backfill
from netwatcher.ingest.repository import EveRepository
from netwatcher.ingest.tailer import EveTailer


logger = logging.getLogger("netwatcher.ingest.service")


class EveService:
    def __init__(self, db, sources, event_stream=None, retention=None, local_networks=None, feeds=None):
        if not isinstance(sources, list) or not 1 <= len(sources) <= 8:
            raise ValueError("Configure between one and eight EVE sources")
        self.db = db
        self.collectors = []
        policy = retention or {}
        self.retention_days = policy.get("days", 30)
        self.cleanup_interval = policy.get("cleanup_interval_seconds", 60)
        if (not isinstance(self.retention_days, int) or isinstance(self.retention_days, bool) or not 1 <= self.retention_days <= 3650 or
                not isinstance(self.cleanup_interval, int) or isinstance(self.cleanup_interval, bool) or not 1 <= self.cleanup_interval <= 3600):
            raise ValueError("Invalid EVE retention schedule")
        budget = {key: policy[key] for key in ("max_records", "max_bytes") if key in policy}
        self.maintenance_error = None
        identities = set()
        for source in sources:
            identity = (source["sensor_id"], source["source_id"])
            if identity in identities:
                raise ValueError("Duplicate EVE source identity")
            identities.add(identity)
            self.collectors.append(EveTailer(EveRepository(db, event_stream, **budget, local_networks=local_networks,
                                                           feeds=feeds),
                                             **source))
        self._stop = asyncio.Event()
        self._tasks = []

    async def start(self):
        if self._tasks:
            raise RuntimeError("EVE service is already started")
        self._stop.clear()
        # 수집을 시작하기 전에 해야 이미 보존된 기록과 새 기록이 두 번 세어지지 않는다.
        for collector in self.collectors:
            try:
                await backfill(self.db, collector.sensor_id, collector.source_id,
                               collector.repository.local_networks)
            except Exception as exc:
                # 실패하면 표시 행이 롤백되어 다음 시작 때 다시 시도한다. 수집은 막지 않는다.
                logger.warning("Observed asset backfill failed for %s/%s: %s",
                               collector.sensor_id, collector.source_id, type(exc).__name__)
        self._tasks = [asyncio.create_task(collector.run(self._stop), name="eve-collector")
                       for collector in self.collectors]
        self._tasks.append(asyncio.create_task(self._cleanup_loop(), name="eve-retention"))

    async def _cleanup_loop(self):
        while not self._stop.is_set():
            try:
                for collector in self.collectors:
                    async with asyncio.timeout(5):
                        await collector.repository.prune(collector.sensor_id, collector.source_id, days=self.retention_days)
                self.maintenance_error = None
            except Exception as exc:
                self.maintenance_error = type(exc).__name__
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.cleanup_interval)
            except TimeoutError:
                continue

    async def stop(self):
        self._stop.set()
        tasks, self._tasks = self._tasks, []
        if tasks:
            await asyncio.gather(*tasks)

    def status(self):
        sources = [collector.status() for collector in self.collectors]
        healthy_tasks = bool(self._tasks) and all(not task.done() for task in self._tasks)
        return self._summarize(sources, healthy_tasks)

    def _summarize(self, sources, healthy_tasks):
        status = "unhealthy" if not healthy_tasks or any(source["status"] == "unhealthy" for source in sources) else \
                 "degraded" if self.maintenance_error or any(source["status"] == "degraded" for source in sources) else "healthy"
        return {"status": status, "sources": sources, "input_mode": "eve", "packet_capture": False,
                "maintenance_error": self.maintenance_error, "retention_days": self.retention_days}

    async def storage_status(self):
        return [dict(sensor_id=collector.sensor_id, source_id=collector.source_id,
                     **await collector.repository.storage_status(collector.sensor_id, collector.source_id))
                for collector in self.collectors]
