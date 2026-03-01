"""대시보드 통계 REST API (Standardized)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Query
from netwatcher.services import visibility as _visibility
from netwatcher.storage.repositories import EventRepository, TrafficStatsRepository

def create_stats_router(stats_repo: TrafficStatsRepository, event_repo: EventRepository) -> APIRouter:
    router = APIRouter(prefix="/stats", tags=["stats"])

    @router.get("/summary")
    async def get_summary():
        traffic = await stats_repo.summary()
        critical = await event_repo.count(severity="CRITICAL")
        warning = await event_repo.count(severity="WARNING")
        info = await event_repo.count(severity="INFO")
        visibility_data = _visibility.state.to_dict() if hasattr(_visibility, 'state') else {"level": "none", "visible_count": 0}
        return {
            "total_packets": traffic.get("total_packets", 0),
            "severity_counts": {"CRITICAL": critical, "WARNING": warning, "INFO": info},
            "protocol_counts": {"TCP": traffic.get("tcp_count", 0), "UDP": traffic.get("udp_count", 0), "ARP": traffic.get("arp_count", 0), "DNS": traffic.get("dns_count", 0)},
            "hosts_visible": visibility_data.get("visible_count", 0),
            "visibility_level": visibility_data.get("level", "none"),
        }

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
