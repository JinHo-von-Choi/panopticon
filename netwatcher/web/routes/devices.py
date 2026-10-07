"""디바이스 인벤토리 REST API (Standardized)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Literal

from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from netwatcher.detection.context_policy import ExpectedFlowRule
from netwatcher.storage.repositories import DeviceRepository
from netwatcher.web.rbac import Role, require_role

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


class ConfirmContextRequest(BaseModel):
    role: Literal['nas', 'backup', 'database', 'printer', 'gateway', 'pc', 'unknown']
    ip_address: str
    expected_version: int = Field(ge=0)
    valid_hours: int = Field(default=168, ge=1, le=720)
    ownership_confirmed: Literal[True]
    evidence: str = Field(min_length=3, max_length=1000)
    expected_flows: list[ExpectedFlowRule] = Field(default_factory=list, max_length=16)

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, value):
        return str(ip_address(value))

    @field_validator('evidence')
    @classmethod
    def validate_evidence(cls, value):
        value = value.strip()
        if len(value) < 3 or '\x00' in value:
            raise ValueError('Confirmation evidence is required')
        return value


def create_devices_router(device_repo: DeviceRepository) -> APIRouter:
    router = APIRouter(prefix="/devices", tags=["devices"])

    @router.get("")
    async def list_devices():
        devices = await device_repo.list_all()
        return {"devices": devices}

    @router.put('/{mac_address}/context')
    async def confirm_context(mac_address: str, body: ConfirmContextRequest,
                              actor: dict = Depends(require_role(Role.ADMIN))):
        if not _valid_mac(mac_address):
            raise HTTPException(400, 'Invalid MAC address')
        if await device_repo.get_by_mac(mac_address) is None:
            raise HTTPException(404, 'Device not found')
        now = datetime.now(timezone.utc)
        profile = {'role': body.role, 'confirmed_by': str(actor.get('sub', 'unknown'))[:255],
                   'confirmed_at': now.isoformat(),
                   'expires_at': (now + timedelta(hours=body.valid_hours)).isoformat(),
                   'evidence': body.evidence,
                   'expected_flows': [rule.model_dump() for rule in body.expected_flows]}
        device = await device_repo.confirm_context(mac_address, body.ip_address,
                                                  body.expected_version, profile)
        if device is None:
            raise HTTPException(409, 'Mapping or confirmation changed; reload and verify ownership')
        context = await device_repo.context_for_device(device)
        return {'ok': True, 'device': device, 'asset_context': context}

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
        device['asset_context'] = await device_repo.context_for_device(device)
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
