"""분리 센서의 조회·설정 변경 API."""

import asyncio
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.rbac import Role, require_role


class EngineChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    base_version: str = Field(pattern=r"^[a-f0-9]{64}$")


class EngineToggle(EngineChange):
    enabled: StrictBool


class EngineConfiguration(EngineChange):
    config: dict


def create_remote_engines_router(control):
    router = APIRouter(prefix="/engines", tags=["engines"])

    async def run(operation):
        try:
            async with asyncio.timeout(20):
                result = await operation()
            if result.get("status") == "unknown":
                raise SensorControlError("sensor_result_unknown", 503)
            return result
        except SensorControlError as exc:
            raise HTTPException(exc.status, {"code": exc.code,
                "message": "센서의 응답을 확인할 수 없습니다. 최신 설정을 조회하세요." if exc.status >= 500
                           else "설정 변경을 승인할 수 없습니다. 권한과 최신 설정을 확인하세요."}) from None
        except TimeoutError:
            raise HTTPException(503, {"code": "sensor_result_unknown",
                "message": "센서의 응답을 확인할 수 없습니다. 최신 설정을 조회하세요."}) from None

    @router.get("")
    async def list_engines(actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.list(actor))

    @router.get("/{name}")
    async def get_engine(name: str, actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.read(name, actor))

    @router.patch("/{name}/toggle")
    async def toggle_engine(name: str, body: EngineToggle, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.change("engine.toggle", name, actor, request_id=str(body.request_id),
                         base_version=body.base_version, updates={"enabled": body.enabled}))

    @router.put("/{name}/config")
    async def configure_engine(name: str, body: EngineConfiguration, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.change("engine.configure", name, actor, request_id=str(body.request_id),
                         base_version=body.base_version, updates=body.config))

    return router
