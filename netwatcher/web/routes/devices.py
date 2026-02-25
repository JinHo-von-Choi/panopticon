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

    @router.get("/devices")
    async def list_devices():
        """등록된 모든 디바이스 목록을 반환한다."""
        devices = await device_repo.list_all()
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

    return router
