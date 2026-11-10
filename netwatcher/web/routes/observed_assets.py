"""Suricata가 관측한 내부 주소 조회."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query

from netwatcher.web.rbac import Role, require_role


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def create_observed_assets_router(database, authorization=None) -> APIRouter:
    router = APIRouter(prefix="/observed-assets", tags=["observed-assets"],
                       dependencies=[Depends(require_role(Role.VIEWER))])

    @router.get("")
    async def list_assets(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000),
                          search: str = Query("", max_length=64)):
        if database is None or getattr(database, "_pool", None) is None:
            raise HTTPException(503, "Database is not connected")
        term = search.strip()
        network = None
        if term:
            try:
                network = str(ipaddress.ip_network(term, strict=False))
            except ValueError:
                raise HTTPException(422, "search must be an IP address or CIDR") from None
        rows = await database.pool.fetch(
            """SELECT sensor_id, source_id, host(ip) AS ip, mac::text AS mac, first_seen, last_seen, evidence,
                      COUNT(*) OVER() AS total
               FROM observed_assets WHERE $3::cidr IS NULL OR ip <<= $3::cidr
               ORDER BY last_seen DESC, ip LIMIT $1 OFFSET $2""", limit, offset, network)
        policy_on = authorization is not None and authorization.enabled

        def asset(row):
            # MAC 없이 관측된 주소는 MAC 목록으로 판정할 수 없어 주소만 대조한다.
            violation = authorization.check(row["mac"] or "", row["ip"]) if policy_on and row["mac"] else (
                authorization.check_ip(row["ip"]) if policy_on else None)
            return {"sensor_id": row["sensor_id"], "source_id": row["source_id"], "ip": row["ip"], "mac": row["mac"],
                    "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
                    "evidence": row["evidence"], "authorized": (violation is None) if policy_on else None,
                    "authorization_reason": violation["reason"] if violation else None}

        return {"total": rows[0]["total"] if rows else 0, "authorization_enabled": policy_on,
                "assets": [asset(row) for row in rows]}

    return router
