"""화이트리스트 관리 REST API.

장치나 IP, 도메인을 탐지 예외 목록에 추가하거나 제거한다.
변경 사항은 YAML 설정 파일에 즉시 영속화된다.

작성자: 최진호
작성일: 2026-03-01
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

if TYPE_CHECKING:
    from netwatcher.detection.whitelist import Whitelist
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger("netwatcher.web.routes.whitelist")


class ToggleRequest(BaseModel):
    type: str  # "ip", "mac", "domain", "ip_range"
    value: str


def create_whitelist_router(
    whitelist: Whitelist,
    yaml_editor: YamlConfigEditor,
) -> APIRouter:
    router = APIRouter(prefix="/whitelist", tags=["whitelist"])

    @router.get("")
    async def get_whitelist():
        """현재 화이트리스트 목록을 조회한다."""
        return whitelist.to_dict()

    @router.post("/toggle")
    async def toggle_item(body: ToggleRequest):
        """항목을 화이트리스트에 추가하거나 제거한다 (토글)."""
        target_type = body.type.lower()
        value = body.value.strip()
        
        if not value:
            raise HTTPException(status_code=400, detail="Value cannot be empty")

        action = "added"
        
        if target_type == "ip":
            if value in whitelist._ips:
                whitelist.remove_ip(value)
                action = "removed"
            else:
                whitelist.add_ip(value)
        
        elif target_type == "mac":
            mac_lower = value.lower()
            if mac_lower in whitelist._macs:
                whitelist.remove_mac(mac_lower)
                action = "removed"
            else:
                whitelist.add_mac(mac_lower)
        
        elif target_type == "domain":
            domain_lower = value.lower()
            if domain_lower in whitelist._domains:
                whitelist.remove_domain(domain_lower)
                action = "removed"
            else:
                whitelist.add_domain(domain_lower)
        
        elif target_type == "ip_range":
            # IP 범위는 리스트 관리가 복잡하므로 여기서는 우선 제외하거나 
            # 단순 문자열 비교로 처리할 수 있음. (현재 Whitelist 클래스는 객체 리스트 사용)
            # 일단은 단순하게 추가만 지원하거나 추후 보완.
            whitelist.add_ip_range(value)
        
        else:
            raise HTTPException(status_code=400, detail=f"Invalid type: {target_type}")

        # YAML 영속화
        try:
            yaml_editor.update_whitelist_config(whitelist.to_dict())
        except Exception as e:
            logger.error("Failed to save whitelist to YAML: %s", e)
            # 메모리는 이미 변경되었으므로 사용자에게 경고하되 성공 반환 가능
        
        return {"status": "ok", "action": action, "type": target_type, "value": value}

    return router
