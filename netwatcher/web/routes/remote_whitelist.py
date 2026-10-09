"""센서의 탐지 예외 목록을 버전 확인 후 명시적으로 추가·제거한다."""

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import StrictBool, Field

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.routes.remote_engines import EngineChange
from netwatcher.web.rbac import Role, require_role


class WhitelistChange(EngineChange):
    type: Literal["ip", "ip_range", "mac", "domain", "suffix"]
    value: str = Field(min_length=1, max_length=253)
    present: StrictBool


def create_remote_whitelist_router(control):
    router = APIRouter(prefix="/whitelist", tags=["whitelist"])

    async def run(operation):
        try:
            async with asyncio.timeout(8):
                result = await operation()
            if result.get("status") == "unknown":
                raise SensorControlError("sensor_result_unknown", 503)
            return result
        except SensorControlError as exc:
            raise HTTPException(exc.status, {"code": exc.code,
                "message": "목록을 다시 조회해 현재 상태를 확인하세요."}) from None
        except TimeoutError:
            raise HTTPException(503, {"code": "sensor_result_unknown",
                "message": "목록을 다시 조회해 현재 상태를 확인하세요."}) from None

    @router.get("")
    async def get_whitelist(actor=Depends(require_role(Role.VIEWER))):
        result = await run(lambda: control.read_whitelist(actor))
        return {**result["whitelist"], "base_version": result["base_version"], "control_process": "separate"}

    @router.put("/entry")
    async def set_entry(body: WhitelistChange, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.set_whitelist(actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"type": body.type, "value": body.value, "present": body.present}))

    return router
