"""디바이스 인벤토리 REST API (Standardized)."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netwatcher.storage.repositories import DeviceRepository

_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _valid_mac(mac: str) -> bool:
    """MAC 주소 형식을 검사한다. 잘못된 값이 DB 계층에 도달하지 않도록 경계에서 막는다."""
    return bool(mac and _MAC_RE.match(mac))


class RegisterDeviceRequest(BaseModel):
    nickname: str
    device_type: str = "unknown"
    is_known: bool = True


class RegisterByMacRequest(BaseModel):
    mac_address: str
    nickname: str = ""
    ip_address: str | None = None
    hostname: str | None = None
    device_type: str = "unknown"
    notes: str = ""
    is_known: bool = True


class UpdateDeviceRequest(BaseModel):
    nickname: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    device_type: str | None = None
    notes: str | None = None
    is_known: bool | None = None


def create_devices_router(device_repo: DeviceRepository) -> APIRouter:
    router = APIRouter(prefix="/devices", tags=["devices"])

    @router.get("")
    async def list_devices():
        devices = await device_repo.list_all()
        return {"devices": devices}

    # 고정 경로를 /{mac_address}보다 먼저 선언해야 "register"가 MAC으로 해석되지 않는다.
    @router.post("/register")
    async def register_by_body(body: RegisterByMacRequest):
        """요청 본문의 MAC 주소로 디바이스를 등록한다."""
        if not _valid_mac(body.mac_address):
            return JSONResponse(
                {"error": f"Invalid MAC address: {body.mac_address}"},
                status_code=400,
            )

        await device_repo.register(
            mac_address=body.mac_address,
            nickname=body.nickname,
            ip_address=body.ip_address,
            hostname=body.hostname,
            notes=body.notes,
        )
        device = await device_repo.update_device(
            body.mac_address,
            device_type=body.device_type,
            is_known=body.is_known,
        )
        return {"ok": True, "device": device}

    @router.get("/{mac_address}")
    async def get_device(mac_address: str):
        device = await device_repo.get_by_mac(mac_address)
        if not device: raise HTTPException(404, "Device not found")
        return {"device": device}

    @router.post("/{mac_address}")
    async def register_device(mac_address: str, body: RegisterDeviceRequest):
        if not _valid_mac(mac_address):
            return JSONResponse(
                {"error": f"Invalid MAC address: {mac_address}"},
                status_code=400,
            )

        await device_repo.register(
            mac_address=mac_address,
            nickname=body.nickname,
            os_hint=body.device_type, # Using os_hint for device_type storage if needed
        )
        # Update device_type directly
        await device_repo.update_device(mac_address, device_type=body.device_type, is_known=body.is_known)
        return {"ok": True}

    @router.put("/{mac_address}")
    async def update_device(mac_address: str, body: UpdateDeviceRequest):
        """등록된 디바이스의 속성을 수정한다."""
        if not _valid_mac(mac_address):
            return JSONResponse(
                {"error": f"Invalid MAC address: {mac_address}"},
                status_code=400,
            )
        if await device_repo.get_by_mac(mac_address) is None:
            return JSONResponse({"error": "Device not found"}, status_code=404)

        device = await device_repo.update_device(
            mac_address,
            **body.model_dump(exclude_none=True),
        )
        return {"ok": True, "device": device}

    return router
