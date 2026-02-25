"""이벤트 라우트: REST API + WebSocket 실시간 스트림."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.storage.repositories import EventRepository

if TYPE_CHECKING:
    from netwatcher.web.auth import AuthManager


def create_events_router(
    event_repo: EventRepository,
    dispatcher: AlertDispatcher,
    pcap_writer: PCAPWriter | None = None,
    auth_manager: "AuthManager | None" = None,
) -> APIRouter:
    """이벤트 REST API 및 WebSocket 라우터 팩토리."""
    router = APIRouter(tags=["events"])

    @router.get("/events")
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
        """필터 조건을 적용하여 이벤트 목록을 페이지네이션으로 반환한다."""
        events = await event_repo.list_recent(
            limit=limit, offset=offset, severity=severity, engine=engine,
            since=since, until=until, search=q, source_ip=source_ip,
        )
        total = await event_repo.count(
            severity=severity, engine=engine,
            since=since, until=until, search=q, source_ip=source_ip,
        )
        return {"events": events, "total": total}

    @router.get("/events/export")
    async def export_events(
        format: str = Query("json", pattern="^(json|csv)$"),
        limit: int = Query(10000, ge=1, le=100000),
        severity: str | None = Query(None),
        engine: str | None = Query(None),
        since: str | None = Query(None),
        until: str | None = Query(None),
    ):
        """이벤트를 JSON 또는 CSV 형식으로 내보낸다."""
        events = await event_repo.list_recent(
            limit=limit, offset=0, severity=severity, engine=engine,
            since=since, until=until,
        )

        if format == "csv":
            import csv
            import io
            output = io.StringIO()
            if events:
                writer = csv.DictWriter(output, fieldnames=events[0].keys())
                writer.writeheader()
                for event in events:
                    # dict 필드 평탄화
                    row = {}
                    for k, v in event.items():
                        if isinstance(v, dict):
                            row[k] = str(v)
                        else:
                            row[k] = v
                    writer.writerow(row)
            from fastapi.responses import Response
            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=events.csv"},
            )

        return {"events": events, "total": len(events)}

    @router.get("/events/{event_id}")
    async def get_event(event_id: int):
        """packet_info 및 metadata를 포함한 전체 이벤트 상세 정보를 반환한다."""
        event = await event_repo.get_by_id(event_id)
        if not event:
            return JSONResponse({"error": "Event not found"}, status_code=404)
        return {"event": event}

    @router.get("/events/{event_id}/pcap")
    async def download_pcap(event_id: int):
        """이벤트에 대한 PCAP 파일이 있으면 다운로드한다."""
        writer = pcap_writer or (dispatcher._pcap_writer if hasattr(dispatcher, '_pcap_writer') else None)
        if not writer:
            return JSONResponse({"error": "PCAP capture not available"}, status_code=404)

        pcap_path = writer.get_pcap_path(event_id)
        if not pcap_path or not Path(pcap_path).exists():
            return JSONResponse({"error": "No PCAP file for this event"}, status_code=404)

        return FileResponse(
            pcap_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=Path(pcap_path).name,
        )

    @router.websocket("/ws/events")
    async def ws_events(websocket: WebSocket):
        """실시간 알림 이벤트를 WebSocket으로 스트리밍한다."""
        if auth_manager and auth_manager.enabled:
            token = websocket.query_params.get("token")
            if not token or not auth_manager.verify_token(token):
                await websocket.close(code=4001, reason="Unauthorized")
                return
        await websocket.accept()
        sub_queue = dispatcher.subscribe_ws()
        try:
            while True:
                msg = await sub_queue.get()
                await websocket.send_text(msg)
        except WebSocketDisconnect:
            pass
        except asyncio.CancelledError:
            pass
        finally:
            dispatcher.unsubscribe_ws(sub_queue)

    return router
