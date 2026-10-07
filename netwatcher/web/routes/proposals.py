"""설정 제안 승인 큐 REST API (PR 10).

역할 규칙 (계획서 "읽기 / 제안 / 승인" 3역할)

| 동작 | 최소 역할 |
|-|-|
| 목록 조회 | viewer (읽기) |
| 제안 접수 | analyst (제안) |
| 승인 / 거절 | admin (승인) |

승인은 곧 설정 쓰기다. 따라서 대시보드 설정 쓰기와 **같은** 역할을 요구하고,
같은 검증 경로를 지난다.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from netwatcher.detection.proposals import (
    SOURCE_HUMAN,
    ProposalError,
    ProposalService,
)
from netwatcher.web.rbac import Role, require_role

logger = logging.getLogger("netwatcher.web.routes.proposals")


class SubmitProposalRequest(BaseModel):
    engine: str = Field(..., min_length=1, max_length=64)
    params: dict[str, Any]
    reason: str = ""


class ValidationRequest(BaseModel):
    normal_run_id: int = Field(..., ge=1)
    attack_run_id: int = Field(..., ge=1)


class DecisionRequest(BaseModel):
    decided_by: str = Field("unknown", max_length=100)
    note: str = ""


def _violations(violations: list[Any]) -> list[dict]:
    return [v.as_dict() if hasattr(v, "as_dict") else {"message": str(v)}
            for v in violations]


def create_proposals_router(service: ProposalService) -> APIRouter:
    """제안 승인 큐 라우터 팩토리."""
    router = APIRouter(prefix="/proposals", tags=["proposals"])

    @router.get("")
    async def list_proposals(
        status: str | None = Query(None, pattern="^(pending|approved|rejected|failed)$"),
        limit: int = Query(50, ge=1, le=200),
        _auth: dict = Depends(require_role(Role.VIEWER, Role.ANALYST, Role.ADMIN)),
    ):
        rows = await service.list_all(limit=limit, status=status)
        return {
            "proposals": rows,
            "validation_required": service.validation_required,
            "total": len(rows),
            "pending": await service.pending_count(),
        }

    @router.post("", status_code=201)
    async def submit_proposal(
        body: SubmitProposalRequest,
        _auth: dict = Depends(require_role(Role.ANALYST, Role.ADMIN)),
    ):
        try:
            proposal_id = await service.submit(
                engine=body.engine,
                params=body.params,
                reason=body.reason,
                source=SOURCE_HUMAN,
            )
        except ProposalError as exc:
            # 스키마 위반 제안은 큐에 들어가지 않는다
            raise HTTPException(
                status_code=400,
                detail={
                    "error": str(exc),
                    "violations": _violations(exc.violations),
                },
            )
        return {"status": "proposed", "id": proposal_id, "engine": body.engine}

    @router.post("/{proposal_id}/validation")
    async def attach_validation(
        proposal_id: int, body: ValidationRequest,
        auth: dict = Depends(require_role(Role.ANALYST, Role.ADMIN)),
    ):
        try:
            result = await service.attach_validation(proposal_id, body.normal_run_id,
                body.attack_run_id, str(auth.get('sub') or 'local'))
            return {"validation": result}
        except ProposalError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)})

    @router.post("/{proposal_id}/approve")
    async def approve_proposal(
        proposal_id: int,
        body: DecisionRequest,
        _auth: dict = Depends(require_role(Role.ADMIN)),
    ):
        return await _decide(service, proposal_id, body, approved=True, actor=str(_auth.get("sub") or "local"))

    @router.post("/{proposal_id}/reject")
    async def reject_proposal(
        proposal_id: int,
        body: DecisionRequest,
        _auth: dict = Depends(require_role(Role.ADMIN)),
    ):
        return await _decide(service, proposal_id, body, approved=False, actor=str(_auth.get("sub") or "local"))

    return router


async def _decide(
    service: ProposalService, proposal_id: int, body: DecisionRequest, approved: bool, actor: str,
):
    try:
        decision = await service.decide(
            proposal_id=proposal_id,
            approved=approved,
            decided_by=actor[:100],
            note=body.note,
        )
    except ProposalError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": str(exc), "violations": _violations(exc.violations)},
        )

    payload = decision.as_dict()
    if decision.approved and not decision.applied:
        # 승인은 됐지만 반영은 실패했다 — 성공으로 위장하지 않는다
        return payload  # 상태 코드 200 이지만 applied=false 와 error 가 함께 담긴다
    return payload
