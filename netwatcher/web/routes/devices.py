"""디바이스 라우트."""

from __future__ import annotations

import re

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netwatcher.storage.repositories import DeviceRepository

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class RegisterDeviceRequest(BaseModel):
    mac_address: str
    nickname: str
    ip_address: str | None = None
    hostname: str | None = None
    os_hint: str | None = None
    notes: str = ""


class UpdateDeviceRequest(BaseModel):
    nickname: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    os_hint: str | None = None
    notes: str | None = None
    is_known: int | None = None


def create_devices_router(device_repo: DeviceRepository) -> APIRouter:
    """디바이스 관리 REST API 라우터 팩토리."""
    router = APIRouter(tags=["devices"])

    @router.get("/inventory/summary")
    async def inventory_summary():
        """기기 타입별 집계, 인가/미인가 카운트, 오늘 신규 기기 수를 반환한다."""
        summary = await device_repo.inventory_summary()
        return summary

    @router.get("/devices")
    async def list_devices(
        device_type: str | None = None,
        is_known: bool | None = None,
    ):
        """등록된 모든 디바이스 목록을 반환한다.

        Query params:
          device_type: 'pc' | 'mobile' | 'printer' | 'router' | 'nas' | 'server' | 'iot' | 'unknown'
          is_known:    true | false — 인가 여부 필터
        """
        devices = await device_repo.list_all()
        if device_type is not None:
            devices = [d for d in devices if d.get("device_type") == device_type]
        if is_known is not None:
            devices = [d for d in devices if d.get("is_known") == is_known]
        return {"devices": devices}

    @router.get("/devices/{mac}")
    async def get_device(mac: str):
        """MAC 주소로 단일 디바이스를 조회한다."""
        device = await device_repo.get_by_mac(mac)
        if not device:
            return JSONResponse({"error": "Device not found"}, status_code=404)
        return {"device": device}

    @router.post("/devices/register")
    async def register_device(req: RegisterDeviceRequest):
        """새 디바이스를 등록하거나 기존 디바이스를 업데이트한다."""
        mac = req.mac_address.strip().lower()
        if not _MAC_RE.match(mac):
            return JSONResponse({"error": "Invalid MAC address format"}, status_code=400)
        if not req.nickname.strip():
            return JSONResponse({"error": "Nickname is required"}, status_code=400)
        device = await device_repo.register(
            mac_address=mac,
            nickname=req.nickname.strip(),
            ip_address=req.ip_address,
            hostname=req.hostname,
            os_hint=req.os_hint,
            notes=req.notes,
        )
        return {"device": device}

    @router.put("/devices/{mac}")
    async def update_device(mac: str, req: UpdateDeviceRequest):
        """기존 디바이스의 정보를 수정한다."""
        existing = await device_repo.get_by_mac(mac)
        if not existing:
            return JSONResponse({"error": "Device not found"}, status_code=404)
        kwargs = req.model_dump(exclude_none=True)
        device = await device_repo.update_device(mac_address=mac, **kwargs)
        return {"device": device}

    @router.get("/devices/{mac}/history")
    async def get_device_ip_history(mac: str):
        """기기의 IP 변경 이력을 반환한다."""
        device = await device_repo.get_by_mac(mac)
        if not device:
            return JSONResponse({"error": "Device not found"}, status_code=404)
        return {
            "mac":        mac,
            "current_ip": device.get("ip_address"),
            "ip_history": device.get("ip_history") or [],
        }

    return router
