"""화이트리스트 관리 REST API.

장치나 IP, 도메인을 탐지 예외 목록에 추가하거나 제거한다.
변경 사항은 YAML 설정 파일에 즉시 영속화된다.

작성자: 최진호
작성일: 2026-03-01
"""

from __future__ import annotations

import logging
import copy
from typing import TYPE_CHECKING, Any

from fastapi import Depends, APIRouter, HTTPException, Request
from pydantic import BaseModel, StrictBool
from netwatcher.services.sensor_whitelist import normalize_entry
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.change_audit import ChangeAudit
from netwatcher.utils.yaml_editor import ConfigurationReadOnlyError

if TYPE_CHECKING:
    from netwatcher.detection.whitelist import Whitelist
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger("netwatcher.web.routes.whitelist")


class ToggleRequest(BaseModel):
    type: str  # "ip", "mac", "domain", "ip_range"
    value: str
    present: StrictBool | None = None


def create_whitelist_router(
    whitelist: Whitelist,
    yaml_editor: YamlConfigEditor,
) -> APIRouter:
    router = APIRouter(prefix="/whitelist", tags=["whitelist"])
    changes = ChangeAudit()

    def snapshot(**args):
        body = args["body"]
        kind = body.type.lower()
        key = {"ip": "ips", "mac": "macs", "domain": "domains", "ip_range": "ip_ranges", "suffix": "domain_suffixes"}.get(kind)
        values = whitelist.to_dict().get(key, [])
        value = body.value.strip().lower()
        if kind in {"ip_range", "suffix"}:
            try:
                value = normalize_entry(kind, value)
            except ValueError:
                return {"type": kind, "valid": False}
        return {"type": kind, "value": value, "present": value in values}

    @router.get("")
    async def get_whitelist():
        """현재 화이트리스트 목록을 조회한다."""
        return whitelist.to_dict()

    @router.post("/toggle", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def toggle_item(body: ToggleRequest, request: Request):
        """항목을 화이트리스트에 추가하거나 제거한다 (토글)."""
        target_type = body.type.lower()
        value = body.value.strip()
        
        if not value:
            raise HTTPException(status_code=400, detail="Value cannot be empty")

        candidate = copy.deepcopy(whitelist)
        action = "added"
        
        if target_type == "ip":
            if body.present is False or body.present is None and value in candidate._ips:
                candidate.remove_ip(value)
                action = "removed"
            else:
                candidate.add_ip(value)
        
        elif target_type == "mac":
            mac_lower = value.lower()
            if body.present is False or body.present is None and mac_lower in candidate._macs:
                candidate.remove_mac(mac_lower)
                action = "removed"
            else:
                candidate.add_mac(mac_lower)
        
        elif target_type == "domain":
            domain_lower = value.lower()
            if body.present is False or body.present is None and domain_lower in candidate._domains:
                candidate.remove_domain(domain_lower)
                action = "removed"
            else:
                candidate.add_domain(domain_lower)
        
        elif target_type == "ip_range":
            try:
                value = normalize_entry(target_type, value)
            except ValueError:
                raise HTTPException(400, "Invalid IP range") from None
            exists = any(str(network) == value for network in candidate._ip_networks)
            if body.present is False or body.present is None and exists:
                candidate._ip_networks = [network for network in candidate._ip_networks if str(network) != value]
                action = "removed"
            elif not exists:
                candidate.add_ip_range(value)

        elif target_type == "suffix":
            try:
                value = normalize_entry(target_type, value)
            except ValueError:
                raise HTTPException(400, "Invalid domain suffix") from None
            exists = value in candidate._domain_suffixes
            if body.present is False or body.present is None and exists:
                candidate._domain_suffixes = [suffix for suffix in candidate._domain_suffixes if suffix != value]
                action = "removed"
            elif not exists:
                candidate._domain_suffixes.append(value)
        
        else:
            raise HTTPException(status_code=400, detail=f"Invalid type: {target_type}")

        try:
            yaml_editor.update_whitelist_config(candidate.to_dict())
        except ConfigurationReadOnlyError:
            raise HTTPException(status_code=503, detail="Configuration is read-only")
        except OSError:
            raise HTTPException(status_code=503, detail="Configuration could not be persisted")
        whitelist.__dict__.update(candidate.__dict__)

        return {"status": "ok", "action": action, "type": target_type, "value": value}

    return router
