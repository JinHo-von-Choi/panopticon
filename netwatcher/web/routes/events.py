"""이벤트 라우트 (Standardized)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from netwatcher.web.rbac import Role, require_role
from fastapi.responses import FileResponse, JSONResponse, Response

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.storage.repositories import EventRepository

if TYPE_CHECKING:
    from netwatcher.web.auth import AuthManager

logger = logging.getLogger("netwatcher.web.routes.events")

# WebSocket 연결 제한 상수
_WS_MAX_CONNECTIONS_PER_IP = 5
_WS_RATE_LIMIT_MSG_PER_MIN = 100


def create_ws_router(
    dispatcher: AlertDispatcher,
    auth_manager: "AuthManager | None" = None,
) -> APIRouter:
    """WebSocket 실시간 이벤트 스트림 라우터 (/api/ws/events)."""
    router = APIRouter(prefix="/ws", tags=["websocket"])
    ws_connections_per_ip: dict[str, int] = defaultdict(int)

    @router.websocket("/events")
    async def ws_events(websocket: WebSocket, token: str | None = None):
        if auth_manager and auth_manager.enabled:
            if not token or not auth_manager.verify_token(token):
                await websocket.close(code=1008)
                return

        client_ip = websocket.client.host if websocket.client else "unknown"

        # IP당 동시 연결 수 제한
        if ws_connections_per_ip[client_ip] >= _WS_MAX_CONNECTIONS_PER_IP:
            logger.warning("WebSocket connection limit exceeded for %s", client_ip)
            await websocket.close(code=1008)
            return

        await websocket.accept()
        ws_connections_per_ip[client_ip] += 1
        q = dispatcher.subscribe_ws()
        msg_count = 0
        window_start = time.monotonic()
        async def wait_disconnect():
            received = 0
            started = time.monotonic()
            while True:
                message = await websocket.receive()
                if message['type'] == 'websocket.disconnect':
                    return
                if time.monotonic() - started >= 60:
                    received = 0
                    started = time.monotonic()
                received += 1
                if received > _WS_RATE_LIMIT_MSG_PER_MIN:
                    await websocket.close(code=1008)
                    return

        disconnect_task = asyncio.create_task(wait_disconnect())
        event_task = asyncio.create_task(q.get())
        try:
            while True:
                try:
                    done, _ = await asyncio.wait((event_task, disconnect_task), timeout=30,
                                                 return_when=asyncio.FIRST_COMPLETED)
                    if disconnect_task in done:
                        disconnect_task.result()
                        break
                    if event_task not in done:
                        await websocket.send_text('{"type":"ping"}')
                        continue
                    msg = event_task.result()
                    event_task = asyncio.create_task(q.get())
                    # 메시지 전송 레이트 리밋
                    now = time.monotonic()
                    if now - window_start >= 60.0:
                        msg_count = 0
                        window_start = now
                    msg_count += 1
                    if msg_count > _WS_RATE_LIMIT_MSG_PER_MIN:
                        continue  # 초과분은 드롭
                    await websocket.send_text(msg)
                except asyncio.TimeoutError:
                    await websocket.send_text('{"type":"ping"}')
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            disconnect_task.cancel()
            event_task.cancel()
            await asyncio.gather(disconnect_task, event_task, return_exceptions=True)
            dispatcher.unsubscribe_ws(q)
            ws_connections_per_ip[client_ip] = max(0, ws_connections_per_ip[client_ip] - 1)
            if ws_connections_per_ip[client_ip] == 0:
                del ws_connections_per_ip[client_ip]

    return router


class EvidencePinRequest(BaseModel):
    enabled: bool = True
    hours: int = Field(default=24, ge=1, le=24)
    reason: str = Field(min_length=3, max_length=500)

    @field_validator('reason')
    @classmethod
    def meaningful_reason(cls, value):
        value = value.strip()
        if len(value) < 3:
            raise ValueError('Review reason required')
        return value



def create_events_router(
    event_repo: EventRepository,
    dispatcher: AlertDispatcher,
    pcap_writer: PCAPWriter | None = None,
    auth_manager: "AuthManager | None" = None,
    device_repo=None,
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
        # 목록에서도 봉투를 함께 준다 — 목록에서 "근거 없는 탐지"를 걸러낼 수 있어야 한다
        return {"events": [_with_evidence(e) for e in events], "total": total}

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

    @router.post('/{event_id}/evidence/pin')
    async def pin_evidence(event_id: int, body: EvidencePinRequest,
                           actor: dict = Depends(require_role(Role.ADMIN))):
        if pcap_writer is None:
            raise HTTPException(503, 'Evidence storage unavailable')
        if not await event_repo.get_by_id(event_id):
            raise HTTPException(404, 'Event not found')
        try:
            return await asyncio.to_thread(pcap_writer.review_pin, event_id,
                actor=str(actor.get('sub') or 'local'), reason=body.reason,
                hours=body.hours, enabled=body.enabled)
        except FileNotFoundError:
            raise HTTPException(404, 'Evidence file unavailable') from None
        except ValueError as error:
            raise HTTPException(409, str(error)) from None

    @router.get('/{event_id}/evidence/file')
    async def download_evidence(event_id: int, actor: dict = Depends(require_role(Role.VIEWER))):
        if pcap_writer is None:
            raise HTTPException(503, 'Evidence storage unavailable')
        if not await event_repo.get_by_id(event_id):
            raise HTTPException(404, 'Event not found')
        path = await asyncio.to_thread(pcap_writer.get_pcap_path, event_id)
        if not path:
            raise HTTPException(404, 'Evidence file unavailable')
        return FileResponse(path, media_type='application/vnd.tcpdump.pcap', filename=Path(path).name)

    @router.get("/{event_id}")
    async def get_event(event_id: int):
        event = await event_repo.get_by_id(event_id)
        if not event: return JSONResponse({"error": "Event not found"}, status_code=404)
        if pcap_writer is not None:
            event["pcap_availability"] = await asyncio.to_thread(pcap_writer.evidence_availability, event_id)
        if device_repo is not None:
            event['asset_context'] = await device_repo.context_for_source(
                event.get('source_ip'), event.get('source_mac'))
        return {"event": _with_evidence(event)}

    return router


# ------------------------------------------------------------------
# 증거 봉투 (PR 09)
# ------------------------------------------------------------------

def _with_evidence(row: dict) -> dict:
    """이벤트 행에 증거 봉투(요약→근거→원자료)를 붙인다.

    ``metadata["evidence"]`` 를 그대로 신뢰하지 않고 **읽을 때 다시 판정**한다.
    계약이 도입되기 전에 저장된 행에도 같은 판정이 적용되어야 "이건 검증 가능한
    탐지인가" 를 과거 데이터에도 물을 수 있다.
    """
    from netwatcher.detection.evidence import classify_alert

    out = dict(row)
    metadata = out.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    # confidence 는 파이프라인이 저장을 위해 붙인 값이라 근거에서 제외한다
    evidence_metadata = {
        k: v for k, v in metadata.items() if k != "evidence"
    }

    class _Row:
        title = out.get("title", "")
        description = out.get("description", "")
        reasoning = out.get("reasoning")
        packet_info = out.get("packet_info") or {}
        metadata = evidence_metadata

    report = classify_alert(_Row)
    out["evidence"] = report.as_dict()
    return out
