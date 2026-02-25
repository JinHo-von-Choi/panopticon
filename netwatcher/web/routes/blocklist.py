"""차단 목록 관리 라우트."""

from __future__ import annotations

import ipaddress
import re

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from netwatcher.storage.repositories import BlocklistRepository
from netwatcher.threatintel.feed_manager import FeedManager


class AddIPRequest(BaseModel):
    ip: str
    notes: str = ""


class RemoveIPRequest(BaseModel):
    ip: str


class AddDomainRequest(BaseModel):
    domain: str
    notes: str = ""


class RemoveDomainRequest(BaseModel):
    domain: str


_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def _is_valid_ip(value: str) -> bool:
    """문자열이 유효한 IPv4/IPv6 주소인지 확인한다."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_valid_domain(value: str) -> bool:
    """문자열이 유효한 도메인 형식인지 확인한다."""
    return bool(_DOMAIN_RE.match(value))


def create_blocklist_router(
    blocklist_repo: BlocklistRepository,
    feed_manager: FeedManager,
) -> APIRouter:
    """차단 목록 관리 REST API 라우터 팩토리."""
    router = APIRouter(tags=["blocklist"])

    @router.get("/blocklist")
    async def list_blocklist(
        entry_type: str | None = None,
        source: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        """차단 목록 항목을 필터링 및 페이지네이션하여 반환한다."""
        entries, total = feed_manager.get_all_entries_paginated(
            entry_type=entry_type,
            search=search,
            source=source,
            limit=limit,
            offset=offset,
        )
        return {"entries": entries, "total": total}

    @router.get("/blocklist/stats")
    async def blocklist_stats():
        """차단 목록 통계(총 IP/도메인/커스텀 수)를 반환한다."""
        return {
            "total_ips": len(feed_manager._blocked_ips),
            "total_domains": len(feed_manager._blocked_domains),
            "custom_ips": len(feed_manager._custom_ips),
            "custom_domains": len(feed_manager._custom_domains),
        }

    @router.post("/blocklist/ip")
    async def add_ip(req: AddIPRequest):
        """커스텀 차단 IP를 추가한다."""
        ip = req.ip.strip()
        if not _is_valid_ip(ip):
            return JSONResponse({"error": "Invalid IP address"}, status_code=400)
        row_id = await blocklist_repo.add("ip", ip, req.notes)
        if row_id is None:
            return JSONResponse({"error": "IP already in blocklist"}, status_code=409)
        feed_manager.add_custom_ip(ip)
        return {"ok": True, "id": row_id}

    @router.delete("/blocklist/ip")
    async def remove_ip(req: RemoveIPRequest):
        """커스텀 차단 IP를 제거한다."""
        ip = req.ip.strip()
        deleted = await blocklist_repo.remove_by_value("ip", ip)
        if not deleted:
            return JSONResponse({"error": "IP not found in custom blocklist"}, status_code=404)
        feed_manager.remove_custom_ip(ip)
        return {"ok": True}

    @router.post("/blocklist/domain")
    async def add_domain(req: AddDomainRequest):
        """커스텀 차단 도메인을 추가한다."""
        domain = req.domain.strip().lower()
        if not _is_valid_domain(domain):
            return JSONResponse({"error": "Invalid domain"}, status_code=400)
        row_id = await blocklist_repo.add("domain", domain, req.notes)
        if row_id is None:
            return JSONResponse({"error": "Domain already in blocklist"}, status_code=409)
        feed_manager.add_custom_domain(domain)
        return {"ok": True, "id": row_id}

    @router.delete("/blocklist/domain")
    async def remove_domain(req: RemoveDomainRequest):
        """커스텀 차단 도메인을 제거한다."""
        domain = req.domain.strip().lower()
        deleted = await blocklist_repo.remove_by_value("domain", domain)
        if not deleted:
            return JSONResponse({"error": "Domain not found in custom blocklist"}, status_code=404)
        feed_manager.remove_custom_domain(domain)
        return {"ok": True}

    return router
