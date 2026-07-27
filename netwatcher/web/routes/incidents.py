"""상관 분석된 알림 그룹에 대한 인시던트 라우트.

조회는 영속 저장소를 우선한다. 인메모리 캐시는 프로세스 수명에 묶여 있어
재시작 후 목록이 비기 때문이다. 저장소가 주입되지 않은 구성에서는 캐시로
폴백한다.

작성자: 최진호
수정일: 2026-07-27
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from netwatcher.detection.correlator import AlertCorrelator

logger = logging.getLogger("netwatcher.web.routes.incidents")

# asyncpg가 돌려주는 배열/시각 값을 JSON 직렬화 가능한 형태로 맞춘다.
_ARRAY_FIELDS = ("alert_ids", "source_ips", "engines", "kill_chain_stages")
_TIME_FIELDS = ("created_at", "updated_at")


def _normalize(row: dict[str, Any]) -> dict[str, Any]:
    """저장소 행을 인메모리 캐시와 동일한 형태로 변환한다."""
    out = dict(row)
    for field in _ARRAY_FIELDS:
        value = out.get(field)
        out[field] = list(value) if value is not None else []
    for field in _TIME_FIELDS:
        value = out.get(field)
        if value is not None and not isinstance(value, str):
            out[field] = value.isoformat()
    return out


def create_incidents_router(correlator: AlertCorrelator) -> APIRouter:
    """인시던트 관리 REST API 라우터 팩토리."""
    router = APIRouter(tags=["incidents"])

    @router.get("/incidents")
    async def list_incidents(
        limit: int = Query(50, ge=1, le=200),
        include_resolved: bool = Query(False),
    ):
        """인시던트 목록을 반환한다."""
        repo = correlator.incident_repo
        if repo is not None:
            try:
                rows = await repo.list_recent(
                    limit=limit, include_resolved=include_resolved
                )
                return {
                    "incidents": [_normalize(r) for r in rows],
                    "total": len(rows),
                    "source": "store",
                }
            except Exception:
                logger.exception("Incident store query failed; serving cached incidents")

        incidents = correlator.get_incidents(
            limit=limit, include_resolved=include_resolved
        )
        return {"incidents": incidents, "total": len(incidents), "source": "cache"}

    @router.get("/incidents/{incident_id}")
    async def get_incident(incident_id: int):
        """단일 인시던트 상세 정보를 반환한다."""
        repo = correlator.incident_repo
        if repo is not None:
            try:
                row = await repo.get_by_id(incident_id)
                if row:
                    return {"incident": _normalize(row)}
            except Exception:
                logger.exception("Incident store lookup failed; falling back to cache")

        incident = correlator.get_incident(incident_id)
        if not incident:
            return JSONResponse({"error": "Incident not found"}, status_code=404)
        return {"incident": incident}

    @router.post("/incidents/{incident_id}/resolve")
    async def resolve_incident(incident_id: int):
        """인시던트를 해결 완료 상태로 변경한다."""
        resolved = correlator.resolve_incident(incident_id)

        repo = correlator.incident_repo
        if repo is not None:
            try:
                if await repo.resolve(incident_id):
                    resolved = True
            except Exception:
                logger.exception("Incident store resolve failed for id=%s", incident_id)

        if resolved:
            return {"status": "ok"}
        return JSONResponse({"error": "Incident not found"}, status_code=404)

    return router
