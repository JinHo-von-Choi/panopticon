"""Threat hunting API 라우트."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from netwatcher.hunting.ioc_correlator import IOCCorrelator
from netwatcher.hunting.mitre_navigator import MITRENavigator
from netwatcher.hunting.timeline import ThreatTimeline
from netwatcher.storage.repositories import EventRepository

logger = logging.getLogger("netwatcher.web.routes.hunting")


def create_hunting_router(
    event_repo: EventRepository,
    ioc_correlator: IOCCorrelator,
    navigator: MITRENavigator,
    timeline: ThreatTimeline,
) -> APIRouter:
    """Threat hunting 라우터를 생성한다."""
    router = APIRouter(prefix="/hunting", tags=["hunting"])

    @router.get("/ioc/{ioc_type}/{ioc_value}")
    async def lookup_ioc(ioc_type: str, ioc_value: str) -> JSONResponse:
        """IOC 교차 상관분석 조회."""
        if ioc_type == "ip":
            report = await ioc_correlator.correlate_ip(ioc_value)
        elif ioc_type == "domain":
            report = await ioc_correlator.correlate_domain(ioc_value)
        else:
            related = await ioc_correlator.find_related(ioc_type, ioc_value)
            return JSONResponse({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "related_events": related,
            })
        return JSONResponse(report.to_dict())

    @router.get("/navigator")
    async def get_navigator_layer(
        name: str = Query("NetWatcher Coverage", description="레이어 이름"),
        hours: int = Query(24, description="조회 시간 범위(시간)"),
    ) -> JSONResponse:
        """MITRE ATT&CK Navigator 레이어 JSON 생성."""
        from datetime import datetime, timedelta, timezone
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        events = await event_repo.list_recent(limit=10000, since=since_str)
        layer = navigator.generate_layer(events, name=name)
        return JSONResponse(layer)

    @router.get("/timeline/{entity_type}/{entity_value}")
    async def get_timeline(
        entity_type: str,
        entity_value: str,
        hours: int = Query(24, description="조회 시간 범위(시간)"),
    ) -> JSONResponse:
        """특정 엔티티의 위협 타임라인 조회."""
        entries = await timeline.build(entity_type, entity_value, hours=hours)
        return JSONResponse([e.to_dict() for e in entries])

    @router.get("/coverage")
    async def get_coverage_gaps(
        hours: int = Query(24, description="조회 시간 범위(시간)"),
    ) -> JSONResponse:
        """탐지 커버리지 갭 분석."""
        from datetime import datetime, timedelta, timezone
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        events = await event_repo.list_recent(limit=10000, since=since_str)
        gaps = navigator.get_coverage_gaps(events)

        from netwatcher.detection.attack_mapping import TTP_REGISTRY
        gap_details = []
        for tid in gaps:
            info = TTP_REGISTRY.get(tid)
            gap_details.append({
                "technique_id": tid,
                "name": info.name if info else "Unknown",
                "tactic": info.tactic if info else "unknown",
                "kill_chain_phase": info.kill_chain_phase if info else "unknown",
            })

        return JSONResponse({
            "total_techniques": len(gaps) + len(set(
                ev.get("mitre_attack_id") for ev in events if ev.get("mitre_attack_id")
            )),
            "covered": len(set(
                ev.get("mitre_attack_id") for ev in events if ev.get("mitre_attack_id")
            )),
            "gaps": gap_details,
        })

    return router
