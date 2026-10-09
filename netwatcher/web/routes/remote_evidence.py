"""분리 센서의 사건 PCAP 조회·다운로드·보존 잠금."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from netwatcher.web.evidence_download import evidence_download
from pydantic import Field, StrictBool, field_validator

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.routes.remote_engines import EngineChange


class EvidenceReview(EngineChange):
    enabled: StrictBool = True
    hours: int = Field(default=24, ge=1, le=24, strict=True)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        value = value.strip()
        if len(value) < 3 or "\x00" in value:
            raise ValueError("Review reason required")
        return value




async def evidence_call(operation):
    try:
        async with asyncio.timeout(8):
            result = await operation()
        if result.get("status") == "unknown":
            raise SensorControlError("sensor_result_unknown", 503)
        return result
    except SensorControlError as exc:
        raise HTTPException(exc.status, {"code": exc.code,
            "message": "증거와 변경 감사 기록을 다시 조회하세요."}) from None
    except TimeoutError:
        raise HTTPException(503, {"code": "sensor_result_unknown",
            "message": "증거 조회 결과를 확인하지 못했습니다."}) from None


def create_remote_evidence_router(control):
    router = APIRouter(prefix="/events", tags=["evidence"])
    slots = asyncio.Semaphore(2)

    @router.get("/{event_id}/evidence")
    async def availability(event_id: int, actor=Depends(require_role(Role.VIEWER))):
        result = await evidence_call(lambda: control.read_evidence(event_id, actor))
        return {**result["evidence"], "control_process": "separate"}

    @router.post("/{event_id}/evidence/pin")
    async def pin(event_id: int, body: EvidenceReview, actor=Depends(require_role(Role.ADMIN))):
        result = await evidence_call(lambda: control.pin_evidence(event_id, actor, request_id=str(body.request_id),
            base_version=body.base_version, updates={"enabled": body.enabled, "hours": body.hours, "reason": body.reason}))
        return {**result, "control_process": "separate"}

    @router.get("/{event_id}/evidence/file")
    async def download(event_id: int, actor=Depends(require_role(Role.VIEWER))):
        async def read_state():
            result = await evidence_call(lambda: control.read_evidence(event_id, actor))
            return result["evidence"]

        async def read_chunk(file_version, offset):
            return await evidence_call(lambda: control.evidence_chunk(event_id, actor,
                file_version=file_version, offset=offset))

        return await evidence_download(event_id, read_state, read_chunk, slots)

    return router
