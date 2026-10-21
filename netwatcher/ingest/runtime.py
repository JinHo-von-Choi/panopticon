"""패킷 캡처와 방화벽 조작 없이 EVE 조사 콘솔을 실행한다."""

import asyncio
import logging
import signal
from pathlib import Path

from fastapi import Depends, HTTPException

from netwatcher.alerts.stream import EventStream
from netwatcher.ingest.service import EveService
from netwatcher.observability.health import HealthChecker
from netwatcher.storage.database import Database
from netwatcher.storage.repositories import (
    BlocklistRepository, DeviceRepository, EventRepository, TrafficStatsRepository,
)
from netwatcher.support import enforce_support
from netwatcher.utils.logging_setup import setup_logging
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.auth import AuthManager
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.server import create_app

logger = logging.getLogger("netwatcher.ingest.runtime")

# 파티션 상태를 하루마다 다시 확인한다.
_PARTITION_CHECK_SECONDS = 24 * 3600


class EveObservation:
    def __init__(self, service, partition_state=None):
        self.service = service
        self._partition_state = partition_state or (lambda: None)

    def snapshot(self):
        status = self.service.status()
        state = "stale" if status["status"] == "unhealthy" else "partial"
        reasons = ["Suricata EVE 파일만 관측합니다. 원래 패킷의 누락과 망 전체의 관측 범위는 확인되지 않습니다."]
        partitions = self._partition_state()
        if partitions:
            if not partitions.get("covered", True):
                state = "unhealthy"
                detail = partitions.get("error") or (
                    f"events 월별 파티션({partitions.get('current_month')})이 없어 "
                    "경보 저장이 중단될 수 있습니다"
                )
                reasons.append(detail)
            elif partitions.get("missing"):
                reasons.append(
                    "events 파티션이 아직 확보되지 않음: " + ", ".join(partitions["missing"])
                )
        return {"state": state, "input_mode": "eve", "sources": status["sources"],
                "reasons": reasons,
                "partitions": partitions,
                "loss": {"link_loss": {"status": "unknown", "reason": "외부 IDS의 패킷 손실은 EVE 파일만으로 측정할 수 없습니다."}},
                "unsupported_measurements": ["nic_drop", "switch_loss", "span_coverage"],
                "no_traffic_observed": None}


class EveHealthChecker(HealthChecker):
    def __init__(self, db, service, observation):
        super().__init__(database=db)
        self.service, self.observation = service, observation

    async def check_all(self):
        result = await super().check_all()
        result["components"]["eve"] = self.service.status()
        statuses = [component["status"] for component in result["components"].values()]
        result["overall_status"] = "unhealthy" if "unhealthy" in statuses else "degraded" if "degraded" in statuses else "healthy"
        return result

    async def readiness(self):
        result = await self.check_all()
        result["components"]["observation"] = {"status": "partial", "scope": "configured_eve_files",
                                               "capture_loss": "unknown"}
        result["ready"] = all(result["components"][name]["status"] == "healthy" for name in ("database", "eve"))
        return result


class EveConsole:
    def __init__(self, config, *, database=None):
        self.config = config
        enforce_support(config)
        # EVE 연결은 외부 IDS를 읽기만 한다. 캡처나 실행 설정을 조용히 무시하지 않는다.
        for path in ("response.enabled", "response_execution.enabled", "response_execution.remote.enabled", "netflow.enabled", "ha.enabled"):
            if str(config.get(path, False)).lower() in {"true", "1", "yes"}:
                raise ValueError(f"{path} is incompatible with EVE read-only mode")
        self.db = database or Database(config)
        self.stream = EventStream()
        self.feeds = self._feed_manager(config)
        self.blocklist = BlocklistRepository(self.db)
        self.events = EventRepository(self.db)
        self.service = EveService(self.db, config.get("input.eve.sources", []), self.stream,
                                  retention=config.get("input.eve.retention", {}),
                                  local_networks=config.get("input.eve.local_networks"), feeds=self.feeds)
        self._feed_task = None
        self._partition_task = None
        self._partition_state = None
        self.observation = EveObservation(self.service, lambda: self._partition_state)
        self.health = EveHealthChecker(self.db, self.service, self.observation)
        self.app = None

    @staticmethod
    def _feed_manager(config):
        """피드는 EVE 기록과 대조만 한다. 피드 설정을 읽지 못하면 대조 없이 수집한다."""
        try:
            from netwatcher.threatintel.feed_manager import FeedManager
            return FeedManager(config)
        except Exception as exc:
            logger.warning("Threat feeds unavailable in EVE mode: %s", type(exc).__name__)
            return None

    async def _refresh_feeds(self):
        from netwatcher.services.maintenance import _positive_hours
        interval = _positive_hours(self.config.get("engines.threat_intel.update_interval_hours", 6)) * 3600
        try:
            self.feeds.load_custom_entries(await self.blocklist.get_all_custom_ips(),
                                           await self.blocklist.get_all_custom_domains())
        except Exception:
            logger.exception("Custom indicators could not be loaded")
        while True:
            try:
                summary = await self.feeds.update_all()
                if not summary.succeeded:
                    logger.error("Threat feed refresh failed (%d feed(s)); keeping previous data", summary.failed)
            except Exception:
                logger.exception("Threat feed refresh failed")
            await asyncio.sleep(interval)

    async def _ensure_partitions(self) -> dict:
        """events 이번 달 파티션을 확보하고 상태를 기록한다.

        월별 파티션이 없으면 해당 월의 INSERT 가 실패해 경보 저장이 조용히
        중단된다. 확보할 수 없으면 기동하지 않는다.
        """
        try:
            state = await self.events.ensure_covered_partitions()
        except Exception as exc:
            # 확인에 실패하면 이전 상태를 유지하지 않는다. 오래된 "정상" 상태가
            # 관측 표면에 남아 있으면 실패가 사라진다.
            self._partition_state = {
                "partitioned": True,
                "covered": False,
                "current_month": None,
                "missing": [],
                "error": f"{type(exc).__name__}: {exc}",
            }
            raise
        self._partition_state = state
        if not state["partitioned"]:
            logger.warning("events 테이블이 파티셔닝되어 있지 않습니다")
        elif state["missing"]:
            logger.warning("events 파티션이 아직 없음: %s", ", ".join(state["missing"]))
        return state

    async def _partition_loop(self) -> None:
        """하루마다 파티션 상태를 다시 확인한다."""
        while True:
            await asyncio.sleep(_PARTITION_CHECK_SECONDS)
            try:
                await self._ensure_partitions()
            except Exception:
                logger.exception("events 파티션 확인 실패")

    def build_app(self):
        from netwatcher.storage.user_accounts import UserAccounts
        app = create_app(self.config, self.events, DeviceRepository(self.db),
                         TrafficStatsRepository(self.db), self.stream,
                         blocklist_repo=self.blocklist if self.feeds else None, feed_manager=self.feeds,
                         auth_manager=AuthManager(self.config, users=UserAccounts(self.db)),
                         observation_service=self.observation, health_checker=self.health,
                         audit_logger=AuditLogger(self.db.pool), audit_required=True)

        @app.get("/api/input/status", dependencies=[Depends(require_role(Role.VIEWER))])
        async def input_status():
            result = self.service.status()
            result["partitions"] = self._partition_state
            try:
                async with asyncio.timeout(5):
                    result["storage"] = await self.service.storage_status()
            except Exception:
                raise HTTPException(503, "EVE storage status is unavailable") from None
            return result

        self.app = app
        return app

    async def run(self):
        import uvicorn
        from netwatcher.utils.i18n import i18n

        setup_logging(self.config)
        i18n.init(Path(__file__).resolve().parents[1] / "web/static/locales",
                  self.config.get("language.default", "ko"))
        await self.db.connect()
        try:
            await self._ensure_partitions()
            app = self.build_app()
            tls = self.config.get("web.tls", {})
            ssl_args = {}
            if tls.get("enabled"):
                if not tls.get("certfile") or not tls.get("keyfile"):
                    raise ValueError("TLS requires a certificate and private key")
                ssl_args = {"ssl_certfile": tls["certfile"], "ssl_keyfile": tls["keyfile"]}
            server = uvicorn.Server(uvicorn.Config(app, host=self.config.get("web.host", "127.0.0.1"),
                port=self.config.get("web.port", 38585), log_level="warning", **ssl_args))
            loop = asyncio.get_running_loop()
            previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                for sig in previous:
                    loop.add_signal_handler(sig, setattr, server, "should_exit", True)
                if self.feeds is not None:
                    self._feed_task = asyncio.create_task(self._refresh_feeds(), name="eve-feeds")
                self._partition_task = asyncio.create_task(self._partition_loop(), name="eve-partitions")
                await self.service.start()
                await server.serve()
            finally:
                if self._feed_task is not None:
                    self._feed_task.cancel()
                    await asyncio.gather(self._feed_task, return_exceptions=True)
                if self._partition_task is not None:
                    self._partition_task.cancel()
                    await asyncio.gather(self._partition_task, return_exceptions=True)
                await self.service.stop()
                for sig, handler in previous.items():
                    loop.remove_signal_handler(sig)
                    signal.signal(sig, handler)
        finally:
            await self.db.close()
