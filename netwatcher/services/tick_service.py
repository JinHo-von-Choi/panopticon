"""TickService - 1초 주기 엔진 틱 루프 및 스니퍼 워치독."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from netwatcher.utils.geoip import enrich_alert_metadata

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.capture.pool import WorkerPool
    from netwatcher.capture.sniffer import PacketSniffer
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.netflow.processor import FlowProcessor
    from netwatcher.services.packet_processor import PacketProcessor

logger = logging.getLogger("netwatcher.services.tick_service")


class TickService:
    """매초 엔진 틱을 발생시키고 스니퍼 상태를 모니터링한다."""

    def __init__(
        self,
        registry: EngineRegistry,
        dispatcher: AlertDispatcher | None,
        sniffer: PacketSniffer | None = None,
    ) -> None:
        """틱 서비스를 초기화한다. 엔진 레지스트리, 디스패처, 스니퍼를 주입받는다."""
        self.registry        = registry
        self.dispatcher      = dispatcher
        self.sniffer         = sniffer
        self._flow_processor: "FlowProcessor | None" = None
        self._worker_pool: "WorkerPool | None" = None
        self._packet_processor: "PacketProcessor | None" = None
        self._task: asyncio.Task | None = None
        self._restart_attempts: int = 0
        self._next_restart_at: float = 0.0

    def set_sniffer(self, sniffer: PacketSniffer) -> None:
        """스니퍼 인스턴스를 나중에 주입한다."""
        self.sniffer = sniffer

    def set_flow_processor(self, processor: "FlowProcessor") -> None:
        """FlowProcessor 인스턴스를 나중에 주입한다."""
        self._flow_processor = processor

    def set_worker_pool(self, pool: "WorkerPool") -> None:
        """워커 풀 인스턴스를 주입한다."""
        self._worker_pool = pool

    def set_packet_processor(self, processor: "PacketProcessor") -> None:
        """PacketProcessor 인스턴스를 주입한다 (워커 알림 수집용)."""
        self._packet_processor = processor

    async def start(self) -> None:
        """틱 루프 비동기 태스크를 시작한다."""
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """틱 루프 태스크를 취소하고 정리한다."""
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        """1초 주기로 엔진 틱을 발생시키고 스니퍼 상태를 모니터링하는 메인 루프."""
        watchdog_counter = 0
        while True:
            await asyncio.sleep(1.0)

            import time
            now = time.time()

            # 멀티프로세스 모드: 워커에서 알림 수집
            if self._packet_processor is not None:
                self._packet_processor.collect_worker_alerts()

            # 패킷 기반 탐지 엔진 틱 (단일프로세스 모드에서만)
            if self._worker_pool is None or not self._worker_pool.is_multiprocess:
                alerts = self.registry.tick()
                for alert in alerts:
                    enrich_alert_metadata(alert.metadata, alert.source_ip, alert.dest_ip)
                    if self.dispatcher:
                        self.dispatcher.enqueue(alert)

            # NetFlow 기반 탐지 엔진 틱
            if self._flow_processor is not None:
                self._flow_processor.on_tick(now)

            # 워커 풀 헬스체크 (10초마다)
            if self._worker_pool is not None and self._worker_pool.is_multiprocess:
                if watchdog_counter % 10 == 9:
                    self._worker_pool.health_check()

            # 스니퍼 워치독 (10초마다)
            watchdog_counter += 1
            if watchdog_counter >= 10:
                watchdog_counter = 0
                if self.sniffer and not self.sniffer.is_running:
                    if now < self._next_restart_at:
                        continue
                    delay = min(300, 10 * (2 ** self._restart_attempts))
                    logger.critical(
                        "Sniffer died unexpectedly — attempting restart "
                        "(attempt %d, next backoff %ds)",
                        self._restart_attempts + 1, delay,
                    )
                    try:
                        self.sniffer.start()
                        logger.info("Sniffer restarted successfully")
                        self._restart_attempts = 0
                        self._next_restart_at = 0.0
                    except Exception:
                        logger.exception("Sniffer restart failed")
                        self._restart_attempts += 1
                        self._next_restart_at = now + delay
