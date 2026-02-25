"""AssetMonitorService — 주기적으로 자산 변경을 감지하고 AlertDispatcher로 알림을 발송한다."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from netwatcher.detection.models import Alert, Severity
from netwatcher.inventory.change_detector import AssetChange, detect_changes

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.storage.repositories import DeviceRepository
    from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.services.asset_monitor")

_ENGINE_NAME = "asset_monitor"


class AssetMonitorService:
    """주기적으로 기기 목록을 스캔하여 자산 변경을 감지하고 경보를 발송한다.

    최초 실행 시에는 베이스라인 스냅샷만 구축하고 알림을 발송하지 않는다.
    이후 실행부터 이전 스냅샷과 현재 상태를 비교하여 변경 사항을 AlertDispatcher 에 전달한다.
    """

    def __init__(
        self,
        device_repo: DeviceRepository,
        dispatcher: AlertDispatcher,
        config: Config,
    ) -> None:
        monitor_cfg = config.section("asset_monitor") or {}
        self._device_repo     = device_repo
        self._dispatcher      = dispatcher
        self._interval        = int(monitor_cfg.get("check_interval_seconds", 60))
        self._offline_minutes = int(monitor_cfg.get("offline_threshold_minutes", 60))
        self._snapshot: dict[str, dict] = {}
        self._initialized     = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """모니터링 루프 비동기 태스크를 시작한다."""
        self._task = asyncio.create_task(self._loop())
        logger.info(
            "AssetMonitorService started (interval=%ds, offline_threshold=%dm)",
            self._interval,
            self._offline_minutes,
        )

    async def stop(self) -> None:
        """모니터링 루프 태스크를 취소하고 정리한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("AssetMonitorService stopped")

    async def _loop(self) -> None:
        """주기적으로 기기 목록을 읽어 변경 사항을 감지하는 메인 루프."""
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self._check()
            except Exception:
                logger.exception("AssetMonitorService check failed")

    async def _check(self) -> None:
        """기기 목록을 한 번 읽어 변경 사항을 처리한다."""
        devices = await self._device_repo.list_all()
        changes, new_snapshot = detect_changes(
            prev            = self._snapshot,
            curr_devices    = devices,
            offline_minutes = self._offline_minutes,
        )
        self._snapshot = new_snapshot

        if not self._initialized:
            # 최초 실행: 베이스라인 스냅샷 구축 완료, 알림 발송하지 않음
            self._initialized = True
            logger.debug(
                "AssetMonitorService baseline built with %d devices",
                len(self._snapshot),
            )
            return

        for change in changes:
            self._dispatch(change)

    def _dispatch(self, change: AssetChange) -> None:
        """AssetChange 를 Alert 로 변환하여 dispatcher 큐에 삽입한다."""
        alert = Alert(
            engine      = _ENGINE_NAME,
            severity    = Severity(change.severity),
            title       = change.title,
            description = change.description,
            source_ip   = change.source_ip,
            source_mac  = change.mac,
            confidence  = 0.9,
            metadata    = {
                "change_type": change.change_type.value,
                "mac":         change.mac,
            },
        )
        self._dispatcher.enqueue(alert)
        logger.info(
            "Asset change [%s]: %s",
            change.change_type.value,
            change.title,
        )
