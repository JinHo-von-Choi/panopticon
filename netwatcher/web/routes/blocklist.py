"""차단 목록 관리 REST API (Standardized)."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netwatcher.storage.repositories import BlocklistRepository
from netwatcher.threatintel.feed_manager import FeedManager

class AddEntryRequest(BaseModel):
    value: str
    notes: str = ""

_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")

def create_blocklist_router(blocklist_repo: BlocklistRepository, feed_manager: FeedManager) -> APIRouter:
    # Prefix는 server.py에서 /api/blocklist로 관리됨
    router = APIRouter(prefix="/blocklist", tags=["blocklist"])

    @router.get("")
    async def list_blocklist(entry_type: str | None = None, source: str | None = None, search: str | None = None, limit: int = 50, offset: int = 0):
        entries, total = feed_manager.get_all_entries_paginated(entry_type=entry_type, search=search, source=source, limit=limit, offset=offset)
        return {"entries": entries, "total": total}

    @router.post("/ip")
    async def add_ip(req: dict[str, Any]):
        value = req.get("ip") or req.get("value")
        if not value: raise HTTPException(400, "IP value required")
        row_id = await blocklist_repo.add("ip", value, req.get("notes", ""))
        feed_manager.add_custom_ip(value)
        return {"ok": True, "id": row_id}

    @router.delete("/ip/{value}")
    async def remove_ip(value: str):
        deleted = await blocklist_repo.remove_by_value("ip", value)
        feed_manager.remove_custom_ip(value)
        return {"ok": True}

    @router.post("/domain")
    async def add_domain(req: dict[str, Any]):
        value = req.get("domain") or req.get("value")
        if not value: raise HTTPException(400, "Domain value required")
        row_id = await blocklist_repo.add("domain", value, req.get("notes", ""))
        feed_manager.add_custom_domain(value)
        return {"ok": True, "id": row_id}

    @router.delete("/domain/{value}")
    async def remove_domain(value: str):
        deleted = await blocklist_repo.remove_by_value("domain", value)
        feed_manager.remove_custom_domain(value)
        return {"ok": True}

    return router
