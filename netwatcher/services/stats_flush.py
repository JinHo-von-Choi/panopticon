"""StatsFlushService - 주기적 트래픽 통계 및 디바이스 버퍼 DB 플러시."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

try:
    from netwatcher.web.metrics import active_devices as _active_devices
    from netwatcher.web.metrics import packets_dropped as _packets_dropped
except ImportError:
    _active_devices  = None
    _packets_dropped = None

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

    def set_sniffer(self, sniffer: PacketSniffer) -> None:
        """스니퍼 인스턴스를 나중에 주입한다."""
        self.sniffer = sniffer

    async def start(self) -> None:
        """통계 플러시 루프 비동기 태스크를 시작한다."""
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """통계 플러시 루프 태스크를 취소하고 정리한다."""
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        """주기적으로 트래픽 카운터와 디바이스 버퍼를 DB에 플러시하는 메인 루프."""
        interval = self.config.get("engines.traffic_anomaly.stats_interval_minutes", 1) * 60
        while True:
            await asyncio.sleep(interval)

            # 트래픽 통계 플러시
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:00Z")
            counters = self.packet_processor.snapshot_and_reset_counters()
            await self.stats_repo.insert(timestamp=ts, **counters)
            logger.debug(
                "Stats flushed: %d pkts, %d bytes",
                counters["total_packets"], counters["total_bytes"],
            )

            # 디바이스 버퍼 플러시 (일괄 upsert)
            batch = self.packet_processor.drain_device_buffer()
            if batch:
                try:
                    await self.device_repo.batch_upsert(batch)
                    # 활성 디바이스 메트릭 업데이트
                    if _active_devices is not None:
                        count = await self.device_repo.count()
                        _active_devices.set(count)
                except Exception:
                    logger.exception("Device batch upsert failed")

            # 스니퍼 드롭 패킷 메트릭 업데이트
            if self.sniffer and _packets_dropped is not None:
                try:
                    _packets_dropped._value.set(self.sniffer.dropped_count)
                except AttributeError:
                    pass
