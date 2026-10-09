"""분리 센서의 설정 제안·검증·승인 API."""

import asyncio
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.rbac import Role, require_role


class ProposalChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    base_version: str = Field(pattern=r"^[a-f0-9]{64}$")


class ProposalSubmission(ProposalChange):
    engine: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    params: dict
    reason: str = Field(default="", max_length=2000)


class ProposalValidation(ProposalChange):
    normal_run_id: int = Field(strict=True, ge=1, le=9223372036854775807)
    attack_run_id: int = Field(strict=True, ge=1, le=9223372036854775807)


class ProposalDecision(ProposalChange):
    note: str = Field(default="", max_length=1000)


def create_remote_proposals_router(control):
    router = APIRouter(prefix="/proposals", tags=["proposals"])

    async def run(operation):
        try:
            async with asyncio.timeout(8):
                result = await operation()
            if result["status"] == "unknown":
                raise SensorControlError("sensor_result_unknown", 503)
            return {**result, "control_process": "separate"}
        except SensorControlError as error:
            raise HTTPException(error.status, {"code": error.code,
                "message": "제안의 상태를 확인할 수 없습니다. 제안과 현재 설정을 다시 조회하세요."}) from None
        except TimeoutError:
            raise HTTPException(503, {"code": "sensor_result_unknown",
                "message": "제안의 처리 결과를 확인할 수 없습니다. 같은 변경을 다시 실행하지 마세요."}) from None

    @router.get("")
    async def list_proposals(status: str | None = Query(None, pattern="^(pending|approved|rejected|failed)$"),
            limit: int = Query(50, ge=1, le=50), offset: int = Query(0, ge=0, le=100000),
            actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.proposals("proposal.list", actor,
            updates={"status": status, "limit": limit, "offset": offset}))

    @router.get("/{proposal_id}")
    async def get_proposal(proposal_id: int, actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.proposals("proposal.entry", actor, updates={"proposal_id": proposal_id}))

    @router.post("", status_code=201)
    async def submit_proposal(body: ProposalSubmission, actor=Depends(require_role(Role.ANALYST))):
        return await run(lambda: control.proposals("proposal.submit", actor, engine=body.engine,
            request_id=str(body.request_id), base_version=body.base_version,
            updates={"params": body.params, "reason": body.reason}))

    @router.post("/{proposal_id}/validation")
    async def attach_validation(proposal_id: int, body: ProposalValidation, actor=Depends(require_role(Role.ANALYST))):
        return await run(lambda: control.proposals("proposal.validate", actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"proposal_id": proposal_id,
                "normal_run_id": body.normal_run_id, "attack_run_id": body.attack_run_id}))

    @router.post("/{proposal_id}/approve")
    async def approve_proposal(proposal_id: int, body: ProposalDecision, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.proposals("proposal.approve", actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"proposal_id": proposal_id, "note": body.note}))

    @router.post("/{proposal_id}/reject")
    async def reject_proposal(proposal_id: int, body: ProposalDecision, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.proposals("proposal.reject", actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"proposal_id": proposal_id, "note": body.note}))

    return router
