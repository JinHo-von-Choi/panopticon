"""대시보드 통계 REST API (Standardized)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, Query
from netwatcher.services import visibility as _visibility
from netwatcher.storage.repositories import EventRepository, TrafficStatsRepository

logger = logging.getLogger("netwatcher.web.routes.stats")

def create_stats_router(stats_repo: TrafficStatsRepository, event_repo: EventRepository, correlator=None, input_mode="native", incident_repo=None) -> APIRouter:
    router = APIRouter(prefix="/stats", tags=["stats"])

    @router.get("/summary")
    async def get_summary():
        traffic = await stats_repo.summary()
        critical = await event_repo.count(severity="CRITICAL")
        warning = await event_repo.count(severity="WARNING")
        info = await event_repo.count(severity="INFO")
        visibility_data = _visibility.state.to_dict() if hasattr(_visibility, 'state') else {"level": "none", "visible_count": 0}
        return {
            "input_mode": input_mode,
            "total_packets": None if input_mode == "eve" else traffic.get("total_packets", 0),
            "severity_counts": {"CRITICAL": critical, "WARNING": warning, "INFO": info},
            "protocol_counts": None if input_mode == "eve" else {"TCP": traffic.get("tcp_count", 0), "UDP": traffic.get("udp_count", 0), "ARP": traffic.get("arp_count", 0), "DNS": traffic.get("dns_count", 0)},
            "hosts_visible": visibility_data.get("visible_count", 0),
            "visibility_level": visibility_data.get("level", "none"),
            "high_risk_count": await _open_critical_incidents(),
        }

    async def _open_critical_incidents() -> int:
        """미해결 CRITICAL 인시던트 수. 상관 분석기가 없으면 0."""
        repo = incident_repo if incident_repo is not None else getattr(correlator, "incident_repo", None)
        if repo is not None:
            try:
                return await repo.count_open(severity="CRITICAL")
            except Exception:
                logger.exception("Incident count query failed")
                raise HTTPException(503, "미해결 사건 수를 조회하지 못했습니다.") from None
        if correlator is None:
            return 0
        try:
            cached = correlator.get_incidents(limit=200, include_resolved=False)
        except Exception:
            logger.exception("Incident cache query failed")
            raise HTTPException(503, "미해결 사건 수를 조회하지 못했습니다.") from None
        return sum(1 for inc in cached if inc.get("severity") == "CRITICAL")

    @router.get("/traffic")
    async def get_traffic(minutes: int = Query(60, ge=1, le=1440)):
        data = await stats_repo.recent(minutes=minutes)
        return {"traffic": data}

    @router.get("/trends")
    async def get_trends(hours: int = Query(24, ge=1, le=168)):
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        by_severity = await event_repo.count_by_severity_since(since)
        by_engine = await event_repo.count_by_engine_since(since)
        return {"hours": hours, "by_severity": by_severity, "by_engine": by_engine}

    return router
