"""디바이스 인벤토리 REST API (Standardized)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netwatcher.storage.repositories import DeviceRepository

class RegisterDeviceRequest(BaseModel):
    nickname: str
    device_type: str = "unknown"
    is_known: bool = True

def create_devices_router(device_repo: DeviceRepository) -> APIRouter:
    router = APIRouter(prefix="/devices", tags=["devices"])

    @router.get("")
    async def list_devices():
        devices = await device_repo.list_all()
        return {"devices": devices}

    @router.get("/{mac_address}")
    async def get_device(mac_address: str):
        device = await device_repo.get_by_mac(mac_address)
        if not device: raise HTTPException(404, "Device not found")
        return {"device": device}

    @router.post("/{mac_address}")
    async def register_device(mac_address: str, body: RegisterDeviceRequest):
        device = await device_repo.register(
            mac_address=mac_address,
            nickname=body.nickname,
            os_hint=body.device_type, # Using os_hint for device_type storage if needed
        )
        # Update device_type directly
        await device_repo.update_device(mac_address, device_type=body.device_type, is_known=body.is_known)
        return {"ok": True}

    return router
