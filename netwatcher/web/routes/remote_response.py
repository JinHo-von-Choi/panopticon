"""독립 실행기의 승인·적용·조회·해제 API."""

import asyncpg
import asyncio
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from netwatcher.response.lifecycle import LifecycleError, MAX_TTL_SECONDS, candidate_hash
from netwatcher.storage.execution_claims import ExecutionClaims
from netwatcher.web.rbac import Role, require_role

OPERATION_TIMEOUT_SECONDS = 8

class AssetScope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset: str = Field(min_length=1, max_length=128)


class RemoteActivate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=64)
    direction: str = Field(default="input", pattern="^(input|output|forward)$")
    ttl_seconds: int = Field(default=300, ge=1, le=MAX_TTL_SECONDS)
    scope: AssetScope
    base_version: str = Field(min_length=1, max_length=64)


class RemoteApprove(RemoteActivate):
    device_id: int = Field(gt=0, lt=2**63, strict=True)
    reason: str = Field(min_length=1, max_length=512)


def _http(error):
    if isinstance(error, LifecycleError):
        return HTTPException(error.status_code, detail={"message": str(error)})
    return HTTPException(503, detail={"message": "조치 상태를 확인할 수 없습니다. 상태 대조가 필요합니다"})


def create_remote_response_router(repository, executor):
    router = APIRouter(tags=["response"])
    claims = ExecutionClaims(repository._db)

    @router.get("/response/capabilities")
    async def capabilities(_role=Depends(require_role(Role.VIEWER))):
        return {"backend": "shadow", "applies_to_os": False, "kernel_expiry_verified": False,
                "mode": "shadow", "execution_process": "separate", "auto_block_enabled": False,
                "worker_reachable": "unknown",
                "notice": "독립 실행기의 shadow 모드입니다. 실제 차단을 적용하지 않습니다."}

    @router.post("/change-proposals/{proposal_id}/approve", status_code=201)
    async def approve(proposal_id: int, req: RemoteApprove, actor=Depends(require_role(Role.ADMIN))):
        try:
            async with asyncio.timeout(5):
                return await claims.approve(proposal_id, actor_id=actor["uid"], actor_version=actor["ver"],
                    device_id=req.device_id, target=req.target, direction=req.direction,
                    ttl_seconds=req.ttl_seconds, scope=req.scope.model_dump(), base_version=req.base_version, reason=req.reason)
        except (LifecycleError, asyncpg.PostgresError, asyncpg.InterfaceError, TimeoutError, ValueError) as error:
            raise _http(error) from None

    async def run_once(action_id, operation, actor, req=None, key=None):
        try:
            command = await claims.command(action_id, operation=operation, actor_id=actor["uid"], actor_version=actor["ver"])
            if req is not None and (command.request().content_hash() != candidate_hash(
                req.target, req.direction, req.ttl_seconds, req.scope.model_dump()) or command.ownership_version != req.base_version):
                raise LifecycleError("승인 내용이나 소유 관계 버전이 다릅니다", 409)
            if key is not None and key != command.idempotency_key:
                raise LifecycleError("승인된 중복 방지 ID가 다릅니다", 409)
            result = await executor.execute(command)
            action = await repository.get(action_id)
            if action is None:
                raise LifecycleError("조치 상태를 확인할 수 없습니다", 503)
            return {"action_id": action_id, "state": action["state"], "expire_at": action["expire_at"],
                    "verified": result.verified, "result_operation": operation, "result": result.as_dict()}
        except (LifecycleError, asyncpg.PostgresError, asyncpg.InterfaceError, TimeoutError, ValueError) as error:
            raise _http(error) from None

    async def run(action_id, operation, actor, req=None, key=None):
        try:
            async with asyncio.timeout(OPERATION_TIMEOUT_SECONDS):
                return await run_once(action_id, operation, actor, req, key)
        except TimeoutError as error:
            raise _http(error) from None

    @router.post("/response-actions/{action_id}/activate")
    async def activate(action_id: int, req: RemoteActivate,
                       idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
                       actor=Depends(require_role(Role.ADMIN))):
        return await run(action_id, "apply", actor, req, idempotency_key)

    @router.post("/response-actions/{action_id}/verify")
    async def verify(action_id: int, actor=Depends(require_role(Role.ADMIN))):
        return await run(action_id, "verify", actor)

    @router.post("/response-actions/{action_id}/remove")
    async def remove(action_id: int, actor=Depends(require_role(Role.ADMIN))):
        return await run(action_id, "remove", actor)

    @router.get("/response-actions/{action_id}")
    async def get_action(action_id: int, _role=Depends(require_role(Role.VIEWER))):
        action = await repository.get(action_id)
        if action is None:
            raise HTTPException(404, "조치 기록을 찾을 수 없습니다")
        bindings = await claims.bindings([action_id])
        return {"action": {**action, "binding": bindings.get(action_id)}, "receipts": await repository.list_receipts(action_id)}

    @router.get("/response-actions")
    async def list_actions(limit: int = 50, _role=Depends(require_role(Role.VIEWER))):
        actions = await repository.list_recent(max(1, min(limit, 200)))
        bindings = await claims.bindings([action["id"] for action in actions])
        return {"actions": [{**action, "binding": bindings.get(action["id"])} for action in actions]}

    return router
