"""분석 경험 라이브러리 API.

사람이 확정한 판정과 실행 대비가 일치할 때만 경험 항목이 생긴다. 항목을
남기는 것은 사람의 몫이다 — 후보를 보고 승인한다.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from netwatcher.detection.experience import ExperienceError, ExperienceService
from netwatcher.web.change_audit import ChangeAudit
from netwatcher.web.rbac import Role, require_role

logger = logging.getLogger("netwatcher.web.routes.experiences")


class AdoptRequest(BaseModel):
    proposal_id: int = Field(..., ge=1)
    review_id: int | None = Field(None, ge=1)


def create_experiences_router(service: ExperienceService) -> APIRouter:
    router = APIRouter(prefix="/experiences", tags=["experiences"])
    changes = ChangeAudit()

    async def snapshot(**args):
        body = args.get("req") or {}
        return {
            "proposal_id": body.get("proposal_id"),
            "review_id": body.get("review_id"),
        }

    @router.get("", dependencies=[Depends(require_role(Role.VIEWER))])
    async def list_experiences(limit: int = Query(50, ge=1, le=200)):
        rows = await service.list_recent(limit)
        return {"experiences": rows, "total": len(rows)}

    @router.get("/candidate", dependencies=[Depends(require_role(Role.ANALYST, Role.ADMIN))])
    async def candidate(
        proposal_id: int = Query(..., ge=1),
        review_id: int | None = Query(None, ge=1),
    ):
        """채택하면 무엇이 남는지 미리 보여준다."""
        try:
            return {"candidate": await service.candidate(proposal_id, review_id)}
        except ExperienceError as exc:
            raise HTTPException(
                status_code=400, detail={"error": str(exc), "reason": exc.reason},
            ) from None

    @router.post("", status_code=201, dependencies=[Depends(require_role(Role.ANALYST, Role.ADMIN))])
    @changes.guard(snapshot)
    async def adopt(req: AdoptRequest, request: Request):
        """사람의 승인을 받아 경험 항목을 남긴다."""
        actor = str(getattr(request.state, "user", "") or "local")
        try:
            result = await service.adopt(req.proposal_id, req.review_id, actor)
        except ExperienceError as exc:
            raise HTTPException(
                status_code=400, detail={"error": str(exc), "reason": exc.reason},
            ) from None
        await _record_ledger(result, actor, request)
        return {"experience": result}

    return router


async def _record_ledger(result: dict, actor: str, request: Request) -> None:
    """경험 반영을 원장에 남긴다. 감사 해시 체인은 감사 기록기가 잇는다."""
    audit = getattr(request.app.state, "audit_logger", None)
    if audit is None:
        return
    details = {
        "experience_id": result.get("id"),
        "engine": result.get("engine"),
        "signature": result.get("signature"),
        "domain": result.get("domain"),
        "cue": result.get("cue"),
        "lesson": result.get("lesson"),
        "confidence": result.get("confidence"),
        "source_proposal_id": result.get("source_proposal_id"),
        "source_review_id": result.get("source_review_id"),
    }
    try:
        await audit.log(
            user=actor[:100], action="analysis_experience_adopted",
            resource=f"/api/experiences/{result.get('id')}", details=details,
            ip=request.client.host if request.client else "",
        )
    except Exception:
        logger.exception("경험 반영 원장 기록 실패")
