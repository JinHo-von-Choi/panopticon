"""대시보드 통계 요약 라우트."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query

from netwatcher.storage.repositories import EventRepository, TrafficStatsRepository


def create_stats_router(
    stats_repo: TrafficStatsRepository,
    event_repo: EventRepository,
) -> APIRouter:
    """대시보드 통계 API 라우터 팩토리."""
    router = APIRouter(tags=["stats"])

    @router.get("/stats")
    async def get_stats():
        """트래픽 요약 및 심각도별 이벤트 수를 반환한다."""
        traffic = await stats_repo.summary()
        total_events = await event_repo.count()
        critical = await event_repo.count(severity="CRITICAL")
        warning = await event_repo.count(severity="WARNING")
        info = await event_repo.count(severity="INFO")
        return {
            "traffic": traffic,
            "events": {
                "total": total_events,
                "critical": critical,
                "warning": warning,
                "info": info,
            },
        }

    @router.get("/stats/traffic")
    async def get_traffic(minutes: int = Query(60, ge=1, le=1440)):
        """지정된 분 수만큼의 최근 트래픽 통계를 반환한다."""
        data = await stats_repo.recent(minutes=minutes)
        return {"traffic": data}

    @router.get("/stats/trends")
    async def get_trends(hours: int = Query(24, ge=1, le=168)):
        """시간에 따른 엔진별 및 심각도별 알림 추세를 반환한다."""
        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        by_severity = await event_repo.count_by_severity_since(since)
        by_engine = await event_repo.count_by_engine_since(since)

        return {
            "hours": hours,
            "by_severity": by_severity,
            "by_engine": by_engine,
        }

    return router
