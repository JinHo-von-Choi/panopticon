"""이벤트 라우트 (Standardized)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.storage.repositories import EventRepository

if TYPE_CHECKING:
    from netwatcher.web.auth import AuthManager

def create_ws_router(
    dispatcher: AlertDispatcher,
    auth_manager: "AuthManager | None" = None,
) -> APIRouter:
    """WebSocket 실시간 이벤트 스트림 라우터 (/api/ws/events)."""
    router = APIRouter(prefix="/ws", tags=["websocket"])

    @router.websocket("/events")
    async def ws_events(websocket: WebSocket, token: str | None = None):
        if auth_manager and auth_manager.enabled:
            if not token or not auth_manager.verify_token(token):
                await websocket.close(code=4001)
                return
        await websocket.accept()
        q = dispatcher.subscribe_ws()
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30)
                    await websocket.send_text(msg)
                except asyncio.TimeoutError:
                    # 연결 유지 ping
                    await websocket.send_text('{"type":"ping"}')
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            dispatcher.unsubscribe_ws(q)

    return router


def create_events_router(
    event_repo: EventRepository,
    dispatcher: AlertDispatcher,
    pcap_writer: PCAPWriter | None = None,
    auth_manager: "AuthManager | None" = None,
) -> APIRouter:
    router = APIRouter(prefix="/events", tags=["events"])

    @router.get("")
    async def list_events(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        severity: str | None = Query(None),
        engine: str | None = Query(None),
        since: str | None = Query(None),
        until: str | None = Query(None),
        q: str | None = Query(None),
        source_ip: str | None = Query(None),
    ):
        events = await event_repo.list_recent(limit=limit, offset=offset, severity=severity, engine=engine, since=since, until=until, search=q, source_ip=source_ip)
        total = await event_repo.count(severity=severity, engine=engine, since=since, until=until, search=q, source_ip=source_ip)
        return {"events": events, "total": total}

    @router.get("/export")
    async def export_events(
        format: str = Query("json", pattern="^(json|csv)$"),
        limit: int = Query(10000, ge=1, le=100000),
        severity: str | None = Query(None),
        engine: str | None = Query(None),
        since: str | None = Query(None),
        until: str | None = Query(None),
    ):
        events = await event_repo.list_recent(limit=limit, offset=0, severity=severity, engine=engine, since=since, until=until)
        if format == "csv":
            import csv, io
            output = io.StringIO()
            if events:
                writer = csv.DictWriter(output, fieldnames=events[0].keys())
                writer.writeheader()
                for e in events:
                    row = {k: (str(v) if isinstance(v, dict) else v) for k, v in e.items()}
                    writer.writerow(row)
            return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=events.csv"})
        return {"events": events, "total": len(events)}

    @router.get("/{event_id}")
    async def get_event(event_id: int):
        event = await event_repo.get_by_id(event_id)
        if not event: return JSONResponse({"error": "Event not found"}, status_code=404)
        return {"event": event}

    return router
