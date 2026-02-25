"""MaintenanceService - 보존 정책 정리, 피드 갱신, 차단 정리 루프."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

try:
    from netwatcher.web.metrics import feed_last_update as _feed_last_update
except ImportError:
    _feed_last_update = None

if TYPE_CHECKING:
    from netwatcher.response.blocker import BlockManager
    from netwatcher.storage.repositories import (
        EventRepository,
        IncidentRepository,
        TrafficStatsRepository,
    )
    from netwatcher.threatintel.feed_manager import FeedManager
    from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.services.maintenance")


class MaintenanceService:
    """주기적 유지보수 실행: 보존 정책 정리, 피드 갱신, 차단 만료."""

    def __init__(
        self,
        config: Config,
        event_repo: EventRepository,
        stats_repo: TrafficStatsRepository,
        incident_repo: IncidentRepository,
        feed_manager: FeedManager | None,
        block_manager: BlockManager | None,
    ) -> None:
        """유지보수 서비스를 초기화한다. 저장소, 피드 매니저, 차단 매니저를 주입받는다."""
        self.config        = config
        self.event_repo    = event_repo
        self.stats_repo    = stats_repo
        self.incident_repo = incident_repo
        self.feed_manager  = feed_manager
        self.block_manager = block_manager

        self._retention_task: asyncio.Task | None = None
        self._feed_task: asyncio.Task | None      = None
        self._block_task: asyncio.Task | None     = None

    async def start(self) -> None:
        """보존 정책 정리, 피드 갱신, 차단 정리 루프를 시작한다."""
        self._retention_task = asyncio.create_task(self._retention_cleanup_loop())
        self._feed_task      = asyncio.create_task(self._feed_refresh_loop())
        self._block_task     = asyncio.create_task(self._block_cleanup_loop())

    async def stop(self) -> None:
        """모든 유지보수 루프 태스크를 취소하고 정리한다."""
        for task in (self._retention_task, self._feed_task, self._block_task):
            if task:
                task.cancel()
        self._retention_task = None
        self._feed_task      = None
        self._block_task     = None

    async def _retention_cleanup_loop(self) -> None:
        """주기적으로 오래된 이벤트, 통계, 인시던트를 정리한다."""
        interval = self.config.get("retention.cleanup_interval_hours", 6) * 3600
        while True:
            await asyncio.sleep(interval)
            try:
                events_days    = self.config.get("retention.events_days", 90)
                stats_days     = self.config.get("retention.traffic_stats_days", 365)
                incidents_days = self.config.get("retention.incidents_days", 180)

                deleted_events = await self.event_repo.delete_older_than(events_days)
                deleted_stats  = await self.stats_repo.delete_older_than(stats_days)
                deleted_incs   = await self.incident_repo.delete_older_than(incidents_days)

                logger.info(
                    "Retention cleanup: %d events, %d stats, %d incidents removed",
                    deleted_events, deleted_stats, deleted_incs,
                )
            except Exception:
                logger.exception("Retention cleanup failed")

    async def _feed_refresh_loop(self) -> None:
        """주기적으로 위협 인텔리전스 피드를 갱신한다."""
        interval = self.config.get("engines.threat_intel.update_interval_hours", 6) * 3600
        while True:
            await asyncio.sleep(interval)
            if self.feed_manager:
                try:
                    await self.feed_manager.update_all()
                    logger.info(
                        "Threat feeds refreshed (%d IPs, %d domains)",
                        len(self.feed_manager._blocked_ips),
                        len(self.feed_manager._blocked_domains),
                    )
                    # Prometheus 메트릭 업데이트
                    if _feed_last_update is not None:
                        _feed_last_update.set(self.feed_manager.last_update_epoch)
                except Exception:
                    logger.exception("Feed refresh failed")

    async def _block_cleanup_loop(self) -> None:
        """주기적으로 만료된 IP 차단을 정리하고 방화벽 규칙을 제거한다."""
        while True:
            await asyncio.sleep(60)
            if self.block_manager and self.block_manager.enabled:
                try:
                    expired_ips = self.block_manager.cleanup_expired()
                    for ip in expired_ips:
                        try:
                            await self.block_manager.unblock(ip)
                        except Exception:
                            logger.debug("Failed to unblock expired IP: %s", ip, exc_info=True)
                    if expired_ips:
                        logger.info("Block cleanup: %d expired blocks removed", len(expired_ips))
                except Exception:
                    logger.exception("Block cleanup loop failed")
