"""확장된 헬스체크: 컴포넌트 상태, 큐 깊이, 업타임, 버전.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import netwatcher

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.storage.database import Database


class HealthChecker:
    """시스템 컴포넌트의 건강 상태를 종합적으로 진단한다.

    Args:
        database: Database 인스턴스.
        dispatcher: AlertDispatcher 인스턴스.
        sniffer: Sniffer 인스턴스 (선택).
        registry: EngineRegistry 인스턴스 (선택).
        redis_client: Redis 클라이언트 (선택).
    """

    def __init__(
        self,
        database: Database | None = None,
        dispatcher: AlertDispatcher | None = None,
        sniffer: Any = None,
        registry: Any = None,
        redis_client: Any = None,
    ) -> None:
        self._database     = database
        self._dispatcher   = dispatcher
        self._sniffer      = sniffer
        self._registry     = registry
        self._redis_client = redis_client
        self._start_time   = time.monotonic()

    async def _check_database(self) -> dict[str, Any]:
        """데이터베이스 연결 상태를 확인한다."""
        if self._database is None:
            return {"status": "unconfigured"}
        try:
            pool = getattr(self._database, "pool", None)
            if pool is None:
                return {"status": "unhealthy", "error": "no pool"}
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            return {
                "status": "healthy",
                "pool_size": pool.get_size(),
                "pool_free": pool.get_idle_size(),
            }
        except Exception as exc:
            return {"status": "unhealthy", "error": str(exc)}

    async def _check_redis(self) -> dict[str, Any]:
        """Redis 연결 상태를 확인한다."""
        if self._redis_client is None:
            return {"status": "unconfigured"}
        try:
            await self._redis_client.ping()
            return {"status": "healthy"}
        except Exception as exc:
            return {"status": "unhealthy", "error": str(exc)}

    def _check_sniffer(self) -> dict[str, Any]:
        """패킷 캡처 스니퍼 상태를 확인한다."""
        if self._sniffer is None:
            return {"status": "unconfigured"}
        running = getattr(self._sniffer, "running", False)
        return {"status": "healthy" if running else "unhealthy"}

    def _check_engines(self) -> dict[str, Any]:
        """탐지 엔진 레지스트리 상태를 확인한다."""
        if self._registry is None:
            return {"status": "unconfigured"}
        engines = getattr(self._registry, "_engines", {})
        enabled = [n for n, e in engines.items() if getattr(e, "enabled", True)]
        return {
            "status":  "healthy" if enabled else "degraded",
            "total":   len(engines),
            "enabled": len(enabled),
        }

    def _check_alert_queue(self) -> dict[str, Any]:
        """알림 큐 상태를 확인한다."""
        if self._dispatcher is None:
            return {"status": "unconfigured"}
        queue = getattr(self._dispatcher, "_queue", None)
        if queue is None:
            return {"status": "unconfigured"}
        qsize = queue.qsize()
        maxsize = queue.maxsize
        return {
            "status":        "healthy" if qsize < maxsize * 0.9 else "degraded",
            "depth":         qsize,
            "max_size":      maxsize,
            "ws_subscribers": len(getattr(self._dispatcher, "_ws_subscribers", set())),
        }

    async def check_all(self) -> dict[str, Any]:
        """모든 컴포넌트의 건강 상태를 종합 진단한다.

        Returns:
            상태 요약 딕셔너리. overall_status는 "healthy", "degraded", "unhealthy" 중 하나.
        """
        db_status    = await self._check_database()
        redis_status = await self._check_redis()
        sniffer_status = self._check_sniffer()
        engines_status = self._check_engines()
        queue_status   = self._check_alert_queue()

        components = {
            "database":    db_status,
            "redis":       redis_status,
            "sniffer":     sniffer_status,
            "engines":     engines_status,
            "alert_queue": queue_status,
        }

        # 전체 상태 결정
        statuses = [c["status"] for c in components.values()]
        if any(s == "unhealthy" for s in statuses):
            overall = "unhealthy"
        elif any(s == "degraded" for s in statuses):
            overall = "degraded"
        else:
            overall = "healthy"

        uptime_seconds = time.monotonic() - self._start_time

        return {
            "overall_status": overall,
            "version":        netwatcher.__version__,
            "uptime_seconds": round(uptime_seconds, 1),
            "components":     components,
        }
