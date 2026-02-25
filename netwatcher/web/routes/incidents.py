"""상관 분석된 알림 그룹에 대한 인시던트 라우트."""

from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from netwatcher.detection.correlator import AlertCorrelator


def create_incidents_router(correlator: AlertCorrelator) -> APIRouter:
    """인시던트 관리 REST API 라우터 팩토리."""
    router = APIRouter(tags=["incidents"])

    @router.get("/incidents")
    async def list_incidents(
        limit: int = Query(50, ge=1, le=200),
        include_resolved: bool = Query(False),
    ):
        """인시던트 목록을 반환한다."""
        incidents = correlator.get_incidents(
            limit=limit, include_resolved=include_resolved
        )
        return {"incidents": incidents, "total": len(incidents)}

    @router.get("/incidents/{incident_id}")
    async def get_incident(incident_id: int):
        """단일 인시던트 상세 정보를 반환한다."""
        incident = correlator.get_incident(incident_id)
        if not incident:
            return JSONResponse({"error": "Incident not found"}, status_code=404)
        return {"incident": incident}

    @router.post("/incidents/{incident_id}/resolve")
    async def resolve_incident(incident_id: int):
        """인시던트를 해결 완료 상태로 변경한다."""
        if correlator.resolve_incident(incident_id):
            return {"status": "ok"}
        return JSONResponse({"error": "Incident not found"}, status_code=404)

    return router
