"""차단 관리 라우트: IP 차단 목록 조회, 추가, 제거.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import ipaddress
import logging

from fastapi import Depends, APIRouter, Request
from fastapi.responses import JSONResponse
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.change_audit import ChangeAudit
from pydantic import BaseModel

from netwatcher.response.blocker import BlockManager

logger = logging.getLogger(__name__)


class BlockRequest(BaseModel):
    ip: str
    reason: str = ""
    duration: int | None = None


def create_blocks_router(block_manager: BlockManager) -> APIRouter:
    """IP 차단 관리 엔드포인트용 라우터를 생성한다."""
    router = APIRouter(tags=["blocks"])
    changes = ChangeAudit()

    def snapshot(**args):
        ip = args["body"].ip if "body" in args else args["ip"]
        entry = next((block for block in block_manager.get_active_blocks() if block["ip"] == ip), None)
        return {"target_ip": ip, "active": entry is not None,
                "duration": entry["duration"] if entry else None,
                "expires_at": entry["expires_at"] if entry else None}

    @router.get("/blocks")
    async def list_blocks():
        """모든 활성 IP 차단 목록을 반환한다."""
        blocks = block_manager.get_active_blocks()
        return {"blocks": blocks, "total": len(blocks)}

    @router.post("/blocks", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def add_block(body: BlockRequest, request: Request):
        """수동으로 IP 주소를 차단한다."""
        # IP 형식 검증
        try:
            ipaddress.ip_address(body.ip)
        except ValueError:
            return JSONResponse(
                {"error": f"Invalid IP address: {body.ip}"},
                status_code=400,
            )

        success = await block_manager.block(
            ip=body.ip,
            reason=body.reason or "Manual block",
            duration=body.duration,
        )
        if not success:
            return JSONResponse(
                {"error": f"Failed to block {body.ip} (whitelisted, already blocked, or limit reached)"},
                status_code=400,
            )
        return {"ok": True, "ip": body.ip}

    @router.delete("/blocks/{ip}", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def remove_block(ip: str, request: Request):
        """지정된 IP에 대한 활성 차단을 제거한다."""
        # IP 형식 검증
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return JSONResponse(
                {"error": f"Invalid IP address: {ip}"},
                status_code=400,
            )

        success = await block_manager.unblock(ip)
        if not success:
            return JSONResponse(
                {"error": f"No active block found for {ip}"},
                status_code=404,
            )
        return {"ok": True, "ip": ip}

    return router
