"""StatsFlushService - 주기적 트래픽 통계 및 디바이스 버퍼 DB 플러시."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

try:
    from netwatcher.web.metrics import active_devices as _active_devices
    from netwatcher.web.metrics import packets_dropped as _packets_dropped
except ImportError:
    _active_devices  = None
    _packets_dropped = None

from netwatcher.services import visibility as _visibility
from netwatcher.web import metrics

if TYPE_CHECKING:
    from netwatcher.capture.sniffer import PacketSniffer
    from netwatcher.services.packet_processor import PacketProcessor
    from netwatcher.storage.repositories import DeviceRepository, TrafficStatsRepository
    from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.services.stats_flush")


class StatsFlushService:
    """주기적으로 트래픽 카운터와 디바이스 버퍼를 데이터베이스에 플러시한다."""

    def __init__(
        self,
        config: Config,
        stats_repo: TrafficStatsRepository,
        device_repo: DeviceRepository,
        packet_processor: PacketProcessor,
        sniffer: PacketSniffer | None = None,
    ) -> None:
        """통계 플러시 서비스를 초기화한다. 저장소, 패킷 프로세서, 스니퍼를 주입받는다."""
        self.config           = config
        self.stats_repo       = stats_repo
        self.device_repo      = device_repo
        self.packet_processor = packet_processor
        self.sniffer          = sniffer
        self._task: asyncio.Task | None = None
        self._pending_stats = None
        self._pending_devices = None
        self._max_pending_age = min(86400, max(1, config.get("storage.max_pending_age_seconds", 300)))
        self.unconfirmed_packets = {"traffic_stats": 0, "devices": 0}
        self._stats_failed = False
        self._devices_failed = False

    def status(self):
        pending = [item for item in (self._pending_stats, self._pending_devices) if item]
        return {"status": "degraded" if self._stats_failed or self._devices_failed else "healthy",
                "pending_stats": self._pending_stats is not None,
                "pending_devices": len(self._pending_devices[2]) if self._pending_devices else 0,
                "oldest_age_seconds": max((time.monotonic() - item[0] for item in pending), default=0),
                "unconfirmed_packets": dict(self.unconfirmed_packets)}

    def set_sniffer(self, sniffer: PacketSniffer) -> None:
        """스니퍼 인스턴스를 나중에 주입한다."""
        self.sniffer = sniffer

    async def start(self) -> None:
        """통계 플러시 루프 비동기 태스크를 시작한다."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """통계 플러시 루프 태스크를 취소하고 정리한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._pending_stats or self._pending_devices:
            logger.warning("Unconfirmed snapshots at shutdown: stats=%s devices=%d",
                           self._pending_stats is not None,
                           len(self._pending_devices[2]) if self._pending_devices else 0)

    async def _loop(self) -> None:
        """주기적으로 트래픽 카운터와 디바이스 버퍼를 DB에 플러시하는 메인 루프."""
        interval = max(.01, self.config.get("engines.traffic_anomaly.stats_interval_minutes", 1) * 60)
        while True:
            await asyncio.sleep(interval)
            try:
                await self.flush_once()
            except Exception:
                logger.exception("Stats flush iteration failed; service remains active")

    async def flush_once(self):
        """확정 전 스냅샷을 유지하고 같은 ID로만 재시도한다."""
        now = time.monotonic()
        for attr in ("_pending_stats", "_pending_devices"):
            pending = getattr(self, attr)
            if pending and now - pending[0] >= self._max_pending_age:
                data = pending[2]
                packets = data.get("total_packets", 0) if attr == "_pending_stats" else sum(d.get("packets", 0) for d in data.values())
                self.unconfirmed_packets["traffic_stats" if attr == "_pending_stats" else "devices"] += packets
                metrics.db_write_total.labels(operation="traffic_stats" if attr == "_pending_stats" else "devices", result="expired_unconfirmed").inc()
                logger.warning("Snapshot expired without confirmation: %s packets=%d", attr, packets)
                setattr(self, attr, None)

        if self._pending_stats is None:
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:00Z")
            counters = self.packet_processor.snapshot_and_reset_counters()
            self._pending_stats = (now, uuid.uuid4(), counters, ts)
        _, flush_id, counters, ts = self._pending_stats
        distinct_src_macs = counters.get("distinct_src_macs", 0)
        started = time.monotonic()
        stored = False
        try:
            async with asyncio.timeout(2):
                await self.stats_repo.insert_snapshot(flush_id=flush_id, timestamp=ts,
                    **{k: v for k, v in counters.items() if k != "distinct_src_macs"})
            stored = True
            self._stats_failed = False
            self._pending_stats = None
            _visibility.state.update(distinct_src_macs, counters["total_packets"])
        except Exception:
            self._stats_failed = True
            logger.debug("Stats snapshot deferred; retaining stable flush ID")
        finally:
            metrics.db_query_duration.labels(operation="traffic_stats_insert").observe(time.monotonic() - started)
            metrics.db_write_total.labels(operation="traffic_stats", result="ok" if stored else "failed").inc()

        if self._pending_devices is None:
            batch = self.packet_processor.drain_device_buffer()
            if batch:
                self._pending_devices = (now, uuid.uuid4(), batch)
        if self._pending_devices is not None:
            _, flush_id, batch = self._pending_devices
            started = time.monotonic()
            stored = False
            try:
                async with asyncio.timeout(2):
                    await self.device_repo.batch_upsert(batch, flush_id=flush_id)
                stored = True
                self._devices_failed = False
                self._pending_devices = None
                if _active_devices is not None:
                    try:
                        async with asyncio.timeout(2):
                            _active_devices.set(await self.device_repo.count())
                    except Exception:
                        logger.debug("Active device count unavailable after confirmed snapshot")
            except Exception:
                self._devices_failed = True
                logger.debug("Device snapshot deferred; retaining stable flush ID")
            finally:
                metrics.db_query_duration.labels(operation="device_batch_upsert").observe(time.monotonic() - started)
                metrics.db_write_total.labels(operation="devices", result="ok" if stored else "failed").inc()

        if self.sniffer and _packets_dropped is not None:
            try:
                _packets_dropped._value.set(self.sniffer.dropped_count)
            except AttributeError:
                pass
