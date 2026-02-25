"""TickService - 1초 주기 엔진 틱 루프 및 스니퍼 워치독."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from netwatcher.utils.geoip import enrich_alert_metadata

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.capture.sniffer import PacketSniffer
    from netwatcher.detection.registry import EngineRegistry

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
        self.registry   = registry
        self.dispatcher = dispatcher
        self.sniffer    = sniffer
        self._task: asyncio.Task | None = None

    def set_sniffer(self, sniffer: PacketSniffer) -> None:
        """스니퍼 인스턴스를 나중에 주입한다."""
        self.sniffer = sniffer

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

            # 엔진 틱
            alerts = self.registry.tick()
            for alert in alerts:
                enrich_alert_metadata(alert.metadata, alert.source_ip, alert.dest_ip)
                if self.dispatcher:
                    self.dispatcher.enqueue(alert)

            # 스니퍼 워치독 (10초마다)
            watchdog_counter += 1
            if watchdog_counter >= 10:
                watchdog_counter = 0
                if self.sniffer and not self.sniffer.is_running:
                    logger.critical("Sniffer died unexpectedly — attempting restart")
                    try:
                        self.sniffer.start()
                        logger.info("Sniffer restarted successfully")
                    except Exception:
                        logger.exception("Sniffer restart failed")
