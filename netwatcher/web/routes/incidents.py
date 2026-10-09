"""상관 분석된 알림 그룹에 대한 인시던트 라우트.

저장소가 있으면 조회와 해결 결과를 저장소에서 확인한다. 저장소 장애를
메모리 캐시로 숨기지 않는다. 저장소 없는 구성에서만 메모리 캐시를 사용한다.

작성자: 최진호
수정일: 2026-07-27
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.web.change_audit import ChangeAudit
from netwatcher.web.rbac import Role, require_role

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


def create_incidents_router(correlator: AlertCorrelator | None = None, *, repository=None) -> APIRouter:
    """인시던트 관리 REST API 라우터 팩토리."""
    router = APIRouter(tags=["incidents"])
    repo = repository if repository is not None else correlator.incident_repo if correlator else None
    if repo is None and correlator is None:
        raise ValueError("사건 저장소 또는 상관 분석기가 필요합니다")
    changes = ChangeAudit()

    async def record(incident_id):
        if repo is None:
            return correlator.get_incident(incident_id)
        try:
            async with asyncio.timeout(2):
                return await repo.get_by_id(incident_id)
        except Exception:
            logger.exception("Incident store lookup failed")
            raise HTTPException(503, "사건을 조회하지 못했습니다. 다시 조회하세요.") from None

    async def snapshot(**args):
        row = await record(args["incident_id"])
        return {"id": args["incident_id"], "exists": row is not None,
                "resolved": bool(row["resolved"]) if row is not None else None}

    @router.get("/incidents")
    async def list_incidents(
        limit: int = Query(50, ge=1, le=200),
        include_resolved: bool = Query(False),
    ):
        """인시던트 목록을 반환한다."""
        if repo is not None:
            try:
                async with asyncio.timeout(2):
                    rows = await repo.list_recent(limit=limit, include_resolved=include_resolved)
                return {
                    "incidents": [_normalize(r) for r in rows],
                    "total": len(rows),
                    "source": "store",
                }
            except Exception:
                logger.exception("Incident store query failed")
                raise HTTPException(503, "사건 목록을 조회하지 못했습니다. 다시 조회하세요.") from None

        incidents = correlator.get_incidents(
            limit=limit, include_resolved=include_resolved
        )
        return {"incidents": incidents, "total": len(incidents), "source": "cache"}

    @router.get("/incidents/{incident_id}")
    async def get_incident(incident_id: int):
        """단일 인시던트 상세 정보를 반환한다."""
        incident = await record(incident_id)
        if not incident:
            return JSONResponse({"error": "Incident not found"}, status_code=404)
        return {"incident": _normalize(incident) if repo is not None else incident}

    @router.post("/incidents/{incident_id}/resolve", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def resolve_incident(incident_id: int, request: Request):
        """인시던트를 해결 완료 상태로 변경한다."""
        if repo is not None:
            try:
                async with asyncio.timeout(2):
                    resolved = await repo.resolve(incident_id)
            except Exception:
                logger.exception("Incident store resolve failed for id=%s", incident_id)
                raise HTTPException(503, "사건 해결 결과를 확인하지 못했습니다. 다시 조회하세요.") from None
            if resolved and correlator is not None:
                correlator.resolve_incident(incident_id, persist=False)
        else:
            resolved = correlator.resolve_incident(incident_id)

        if resolved:
            return {"status": "ok"}
        return JSONResponse({"error": "Incident not found"}, status_code=404)

    return router
