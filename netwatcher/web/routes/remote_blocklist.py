"""관리자의 위협 지표 변경을 센서에 전달하고 확정된 결과만 반환한다."""

import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, StrictBool

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.routes.remote_engines import EngineChange


class BlocklistChange(EngineChange):
    type: Literal["ip", "domain"]
    value: str = Field(min_length=1, max_length=253)
    present: StrictBool
    notes: str = Field(default="", max_length=2048)


def create_remote_blocklist_router(control):
    router = APIRouter(prefix="/blocklist", tags=["blocklist"])

    async def run(operation):
        try:
            async with asyncio.timeout(8):
                result = await operation()
            if result.get("status") == "unknown":
                raise SensorControlError("sensor_result_unknown", 503)
            return result
        except SensorControlError as exc:
            raise HTTPException(exc.status, {"code": exc.code,
                "message": "현재 목록과 변경 기록을 확인한 뒤 다시 시도하세요."}) from None
        except TimeoutError:
            raise HTTPException(503, {"code": "sensor_result_unknown",
                "message": "현재 목록과 변경 기록을 확인한 뒤 다시 시도하세요."}) from None

    @router.get("")
    async def list_entries(entry_type: Literal["ip", "domain"] | None = None,
            source: Literal["custom", "feed"] | None = None, search: str | None = Query(default=None, max_length=253),
            limit: int = Query(default=50, ge=0, le=100), offset: int = Query(default=0, ge=0, le=2147483647),
            actor=Depends(require_role(Role.VIEWER))):
        result = await run(lambda: control.read_blocklist(actor, entry_type=entry_type, source=source,
            search=search, limit=limit, offset=offset))
        return {"entries": result["entries"], "total": result["total"], "control_process": "separate"}

    @router.get("/stats")
    async def get_stats(actor=Depends(require_role(Role.VIEWER))):
        result = await run(lambda: control.blocklist_stats(actor))
        return {**result["stats"], "control_process": "separate"}

    @router.get("/entry")
    async def get_entry(entry_type: Literal["ip", "domain"], value: str = Query(min_length=1, max_length=253),
            actor=Depends(require_role(Role.VIEWER))):
        return await run(lambda: control.blocklist_entry(actor, entry_type=entry_type, value=value))

    @router.put("/entry")
    async def set_entry(body: BlocklistChange, actor=Depends(require_role(Role.ADMIN))):
        return await run(lambda: control.set_blocklist(actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"type": body.type, "value": body.value,
                "present": body.present, "notes": body.notes}))

    return router
