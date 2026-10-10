"""관측 대시보드 조회 API. 등록된 패널만 읽기 전용 트랜잭션에서 집계한다."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from decimal import Decimal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query

from netwatcher.observability.panels import MAX_RANGE_SECONDS, PANELS, bucket_seconds
from netwatcher.web.rbac import Role, require_role

MAX_PANELS_PER_REQUEST = 24
QUERY_TIMEOUT = "5s"


def _utc_iso(value) -> str:
    """풀 연결은 timestamptz를 문자열로 돌려준다. 어떤 형태든 UTC ISO 8601로 맞춘다."""
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return moment.astimezone(timezone.utc).isoformat()


def _number(value):
    return float(value) if isinstance(value, (Decimal, int, float)) else value


def _shape(panel, rows):
    if panel.kind == "timeseries":
        series: dict[str, list] = {}
        for row in rows:
            series.setdefault(str(row["series"]), []).append([_utc_iso(row["bucket"]), _number(row["value"])])
        return {"series": series}
    if panel.kind == "heatmap":
        return {"cells": [{"x": row["x"], "y": row["y"], "value": _number(row["value"])} for row in rows]}
    return {"rows": [{"label": row["label"], "value": _number(row["value"])} for row in rows]}


def create_observability_router(database, input_mode: str) -> APIRouter:
    router = APIRouter(prefix="/observability", tags=["observability"],
                       dependencies=[Depends(require_role(Role.VIEWER))])
    # 대시보드 갱신이 수집·리스 갱신과 연결을 다투지 않도록 동시 조회를 묶는다.
    gate = asyncio.Semaphore(2)

    @router.get("/panels")
    async def panels():
        return {"input_mode": input_mode, "panels": {
            name: {"kind": panel.kind, "unit": panel.unit, "supported": input_mode in panel.modes}
            for name, panel in PANELS.items()}}

    @router.get("/query")
    async def query(
        panels: str = Query(..., min_length=1, max_length=512),
        start: datetime = Query(..., alias="from"),
        end: datetime = Query(..., alias="to"),
        tz: str = Query("UTC", max_length=64),
    ):
        names = [name for name in panels.split(",") if name]
        if not names or len(names) > MAX_PANELS_PER_REQUEST or len(set(names)) != len(names):
            raise HTTPException(422, "panels must list 1-24 distinct panel names")
        unknown = [name for name in names if name not in PANELS]
        if unknown:
            raise HTTPException(422, "Unknown panels: " + ",".join(unknown[:5]))
        if start.tzinfo is None or end.tzinfo is None:
            raise HTTPException(422, "from and to need a timezone")
        span = (end - start).total_seconds()
        if span <= 0 or span > MAX_RANGE_SECONDS:
            raise HTTPException(422, "Range must be positive and at most 92 days")
        try:
            ZoneInfo(tz)
        except (ZoneInfoNotFoundError, ValueError):
            raise HTTPException(422, "Unknown timezone") from None
        pool = getattr(database, "_pool", None)
        if pool is None:
            raise HTTPException(503, "Database is not connected")
        bucket = bucket_seconds(span)
        values = {"from": start, "to": end, "bucket": float(bucket), "tz": tz}
        results = {}
        async with gate:
            async with pool.acquire() as conn, conn.transaction(readonly=True):
                await conn.execute(f"SET LOCAL statement_timeout = '{QUERY_TIMEOUT}'")
                for name in names:
                    panel = PANELS[name]
                    base = {"kind": panel.kind, "unit": panel.unit}
                    if input_mode not in panel.modes:
                        results[name] = base | {"state": "unsupported", "reason": f"{input_mode}_mode"}
                        continue
                    try:
                        # 한 패널의 시간 초과가 같은 트랜잭션의 다른 패널을 망치지 않도록 세이브포인트로 감싼다.
                        async with conn.transaction():
                            rows = await conn.fetch(panel.sql, *[values[arg] for arg in panel.args])
                    except asyncpg.QueryCanceledError:
                        results[name] = base | {"state": "timeout"}
                        continue
                    results[name] = base | {"state": "ok"} | _shape(panel, rows)
        return {"as_of": datetime.now(timezone.utc).isoformat(), "from": start.isoformat(), "to": end.isoformat(),
                "bucket_seconds": bucket, "tz": tz, "panels": results}

    return router
