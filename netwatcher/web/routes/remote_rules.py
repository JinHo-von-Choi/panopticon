"""분리 센서의 시그니처 규칙 조회·활성 상태·파일 재로드 API."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import StrictBool

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.routes.remote_engines import EngineChange


class RuleState(EngineChange):
    rule_id: str
    enabled: StrictBool


def create_remote_rules_router(control):
    router = APIRouter(prefix="/rules", tags=["rules"])

    async def run(operation):
        try:
            async with asyncio.timeout(8):
                result = await operation()
            if result.get("status") == "unknown":
                raise SensorControlError("sensor_result_unknown", 503)
            return {**result, "control_process": "separate"}
        except SensorControlError as exc:
            raise HTTPException(exc.status, {"code": exc.code,
                "message": "최신 규칙과 변경 감사 기록을 조회하세요."}) from None
        except TimeoutError:
            raise HTTPException(503, {"code": "sensor_result_unknown",
                "message": "최신 규칙과 변경 감사 기록을 조회하세요."}) from None

    @router.get("")
    async def rules(limit: int = Query(default=50, ge=1, le=50), offset: int = Query(default=0, ge=0, le=2147483647),
                    actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.read_rules(actor, limit=limit, offset=offset))

    @router.get("/entry")
    async def entry(rule_id: str = Query(min_length=1, max_length=128), actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.rule_entry(actor, rule_id=rule_id))

    @router.put("/entry")
    async def set_state(body: RuleState, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.change_rules("rules.set", actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"rule_id": body.rule_id, "enabled": body.enabled}))

    @router.post("/reload")
    async def reload(body: EngineChange, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.change_rules("rules.reload", actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={}))

    @router.get("/{rule_id}")
    async def detail(rule_id: str, actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.rule_entry(actor, rule_id=rule_id))

    return router
