"""MaintenanceService - 보존 정책 정리, 피드 갱신, 차단 정리 루프."""

from __future__ import annotations

import asyncio
import logging
import math
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

# 주기가 0 이거나 음수면 asyncio.sleep 이 즉시 반환해 루프가 회신한다.
# 최소값을 두어 busy loop 를 막는다.
_MIN_INTERVAL_SECONDS = 60.0


def _positive_hours(value, default: float = 6.0) -> float:
    """설정된 시간(시간 단위)을 양수로 정규화한다."""
    try:
        hours = float(value)
    except (TypeError, ValueError):
        logger.warning("갱신 주기를 확인할 수 없어 기본값 %s 시간을 사용합니다", default)
        return default
    if not math.isfinite(hours) or hours <= 0:
        logger.warning(
            "주기 값이 양수가 아니다(%r) — 기본값 %s 시간을 사용한다", value, default,
        )
        return default
    return max(hours * 3600, _MIN_INTERVAL_SECONDS) / 3600


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
        *, retention_enabled: bool = True,
    ) -> None:
        """유지보수 서비스를 초기화한다. 저장소, 피드 매니저, 차단 매니저를 주입받는다."""
        self.retention_enabled = retention_enabled
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
        if self.retention_enabled:
            self._retention_task = asyncio.create_task(self._retention_cleanup_loop())
        self._feed_task      = asyncio.create_task(self._feed_refresh_loop())
        self._block_task     = asyncio.create_task(self._block_cleanup_loop())

    async def stop(self) -> None:
        """모든 유지보수 루프 태스크를 취소하고 정리한다."""
        tasks = [task for task in (self._retention_task, self._feed_task, self._block_task) if task]
        for task in tasks:
            if task:
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._retention_task = None
        self._feed_task      = None
        self._block_task     = None

    async def _retention_cleanup_loop(self) -> None:
        """주기적으로 오래된 이벤트, 통계, 인시던트를 정리한다."""
        interval = _positive_hours(self.config.get("retention.cleanup_interval_hours", 6)) * 3600
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
        """주기적으로 위협 인텔리전스 피드를 갱신한다.

        첫 갱신도 주기만큼 기다리지 않는다. 기동 직후 갱신이 한 번도 일어나지
        않은 채 threat_intel 엔진이 빈 목록으로 돌면, "탐지가 안 잡힌 것" 과
        "지표가 없는 것" 을 구분할 수 없다 (PR 07).
        """
        interval = _positive_hours(
            self.config.get("engines.threat_intel.update_interval_hours", 6),
            default=6.0,
        ) * 3600

        while True:
            if self.feed_manager:
                try:
                    summary = await self.feed_manager.update_all()
                    if summary.succeeded:
                        logger.info(
                            "Threat feeds refreshed (%d IPs, %d domains)",
                            summary.blocked_ips,
                            summary.blocked_domains,
                        )
                    else:
                        # 상태는 유지되지만 지표는 갱신되지 않았다
                        logger.error(
                            "Threat feed refresh failed (%d feed(s)); keeping previous data "
                            "(%d IPs, %d domains)",
                            summary.failed, summary.blocked_ips, summary.blocked_domains,
                        )
                    if _feed_last_update is not None:
                        _feed_last_update.set(self.feed_manager.last_update_epoch)
                except Exception:
                    logger.exception("Feed refresh failed")
            await asyncio.sleep(interval)

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
