"""화이트리스트 관리 REST API."""

from __future__ import annotations

from fastapi import APIRouter, Body
from fastapi.responses import JSONResponse

from netwatcher.detection.whitelist import Whitelist


def create_whitelist_router(whitelist: Whitelist) -> APIRouter:
    """화이트리스트 관리 REST API 라우터 팩토리."""
    router = APIRouter(tags=["whitelist"])

    @router.get("/whitelist")
    async def get_whitelist():
        """현재 화이트리스트 전체를 반환한다."""
        return {"whitelist": whitelist.to_dict()}

    @router.post("/whitelist/ip")
    async def add_ip(ip: str = Body(..., embed=True)):
        """IP 주소를 화이트리스트에 추가한다."""
        whitelist.add_ip(ip)
        return {"status": "ok", "added": "ip", "value": ip}

    @router.delete("/whitelist/ip")
    async def remove_ip(ip: str = Body(..., embed=True)):
        """IP 주소를 화이트리스트에서 제거한다."""
        whitelist.remove_ip(ip)
        return {"status": "ok", "removed": "ip", "value": ip}

    @router.post("/whitelist/mac")
    async def add_mac(mac: str = Body(..., embed=True)):
        """MAC 주소를 화이트리스트에 추가한다."""
        whitelist.add_mac(mac)
        return {"status": "ok", "added": "mac", "value": mac}

    @router.delete("/whitelist/mac")
    async def remove_mac(mac: str = Body(..., embed=True)):
        """MAC 주소를 화이트리스트에서 제거한다."""
        whitelist.remove_mac(mac)
        return {"status": "ok", "removed": "mac", "value": mac}

    @router.post("/whitelist/domain")
    async def add_domain(domain: str = Body(..., embed=True)):
        """도메인을 화이트리스트에 추가한다."""
        whitelist.add_domain(domain)
        return {"status": "ok", "added": "domain", "value": domain}

    @router.delete("/whitelist/domain")
    async def remove_domain(domain: str = Body(..., embed=True)):
        """도메인을 화이트리스트에서 제거한다."""
        whitelist.remove_domain(domain)
        return {"status": "ok", "removed": "domain", "value": domain}

    @router.post("/whitelist/ip_range")
    async def add_ip_range(cidr: str = Body(..., embed=True)):
        """IP 대역(CIDR)을 화이트리스트에 추가한다."""
        whitelist.add_ip_range(cidr)
        return {"status": "ok", "added": "ip_range", "value": cidr}

    return router
