"""차단 목록 관리 REST API (Standardized)."""

from __future__ import annotations

import ipaddress
import re
import hashlib
from typing import Any

from fastapi import Depends, APIRouter, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.change_audit import ChangeAudit
from pydantic import BaseModel

from netwatcher.storage.repositories import BlocklistRepository
from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.services.sensor_blocklist import entry_metadata

class AddEntryRequest(BaseModel):
    value: str
    notes: str = ""

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")

def create_blocklist_router(blocklist_repo: BlocklistRepository, feed_manager: FeedManager) -> APIRouter:
    # Prefix는 server.py에서 /api/blocklist로 관리됨
    router = APIRouter(prefix="/blocklist", tags=["blocklist"])
    changes = ChangeAudit()

    async def snapshot(**args):
        entry_type = "domain" if "/domain" in args["request"].url.path else "ip"
        value = args.get("value") or args.get("req", {}).get(entry_type) or args.get("req", {}).get("value")
        if not isinstance(value, str):
            raise HTTPException(400, "Entry value required")
        entry = await blocklist_repo.get_entry(entry_type, value)
        return {"type": entry_type, "value": value, "present": entry is not None,
                "notes_sha256": hashlib.sha256(str(entry["notes"]).encode()).hexdigest() if entry else None}

    @router.get("")
    async def list_blocklist(entry_type: str | None = None, source: str | None = None, search: str | None = None, limit: int = 50, offset: int = 0):
        entries, total = feed_manager.get_all_entries_paginated(entry_type=entry_type, search=search, source=source, limit=limit, offset=offset)
        return {"entries": entries, "total": total}

    @router.get("/stats")
    async def blocklist_stats():
        """로드된 차단 항목 수를 유형·출처별로 집계한다."""
        return {
            "total_ips":      len(feed_manager._blocked_ips),
            "total_domains":  len(feed_manager._blocked_domains),
            "custom_ips":     len(feed_manager._custom_ips),
            "custom_domains": len(feed_manager._custom_domains),
        }

    @router.get("/entry", dependencies=[Depends(require_role(Role.VIEWER))])
    async def entry_details(entry_type: str, value: str = Query(min_length=1, max_length=253)):
        if entry_type not in {"ip", "domain"}:
            raise HTTPException(400, "Invalid indicator type")
        row = await blocklist_repo.get_entry(entry_type, value)
        return {"entry": {"type": entry_type, "value": value, "present": row is not None,
            **entry_metadata(row)}}

    @router.post("/ip", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def add_ip(req: dict[str, Any], request: Request):
        value = req.get("ip") or req.get("value")
        if not value: raise HTTPException(400, "IP value required")
        if not _is_valid_ip(value):
            return JSONResponse({"error": f"Invalid IP address: {value}"}, status_code=400)
        row_id = await blocklist_repo.add("ip", value, req.get("notes", ""))
        feed_manager.add_custom_ip(value)
        return {"ok": True, "id": row_id}

    @router.delete("/ip", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def remove_ip_by_body(req: dict[str, Any], request: Request):
        value = req.get("ip") or req.get("value")
        if not value: raise HTTPException(400, "IP value required")
        return await _remove_ip(value)

    @router.delete("/ip/{value}", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def remove_ip(value: str, request: Request):
        return await _remove_ip(value)

    @router.post("/domain", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def add_domain(req: dict[str, Any], request: Request):
        value = req.get("domain") or req.get("value")
        if not value: raise HTTPException(400, "Domain value required")
        if not _DOMAIN_RE.match(value):
            return JSONResponse({"error": f"Invalid domain: {value}"}, status_code=400)
        row_id = await blocklist_repo.add("domain", value, req.get("notes", ""))
        feed_manager.add_custom_domain(value)
        return {"ok": True, "id": row_id}

    @router.delete("/domain", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def remove_domain_by_body(req: dict[str, Any], request: Request):
        value = req.get("domain") or req.get("value")
        if not value: raise HTTPException(400, "Domain value required")
        return await _remove_domain(value)

    @router.delete("/domain/{value}", dependencies=[Depends(require_role(Role.ADMIN))])
    @changes.guard(snapshot)
    async def remove_domain(value: str, request: Request):
        return await _remove_domain(value)

    async def _remove_ip(value: str) -> dict[str, bool]:
        await blocklist_repo.remove_by_value("ip", value)
        feed_manager.remove_custom_ip(value)
        return {"ok": True}

    async def _remove_domain(value: str) -> dict[str, bool]:
        await blocklist_repo.remove_by_value("domain", value)
        feed_manager.remove_custom_domain(value)
        return {"ok": True}

    return router


def _is_valid_ip(value: str) -> bool:
    """단일 IP 또는 CIDR 표기를 허용한다."""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
