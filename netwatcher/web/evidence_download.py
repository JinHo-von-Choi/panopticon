"""사건 ID로 읽는 증거의 크기·시간·동시 연결을 제한한다."""

import asyncio
import base64
import hashlib
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

class EvidenceResponse(StreamingResponse):
    def __init__(self, *args, release, **kwargs):
        super().__init__(*args, **kwargs)
        self._release = release

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._release()



async def evidence_download(event_id, read_state, read_chunk, slots):
    if slots.locked():
        raise HTTPException(429, "동시에 내려받을 수 있는 증거는 2개입니다.")
    await slots.acquire()
    try:
        state = await read_state()
        if state["state"] != "available":
            raise HTTPException(404, "보관된 증거 파일이 없습니다.")
        first = await read_chunk(state["file_version"], 0)
    except BaseException:
        slots.release()
        raise

    released = False
    def release():
        nonlocal released
        if not released:
            released = True
            slots.release()

    async def stream():
        try:
            async with asyncio.timeout(60):
                chunk = first
                digest = hashlib.sha256()
                while True:
                    if chunk["size"] != state["size"] or chunk["sha256"] != state["sha256"]:
                        raise ValueError("Evidence stream identity changed")
                    raw = base64.b64decode(chunk["data"], validate=True)
                    digest.update(raw)
                    # 마지막 바이트를 보내기 전에 전체 해시를 확인한다.
                    if chunk["next_offset"] == state["size"]:
                        if digest.hexdigest() != state["sha256"]:
                            raise ValueError("Evidence stream checksum mismatch")
                        yield raw
                        return
                    yield raw
                    chunk = await read_chunk(state["file_version"], chunk["next_offset"])
        finally:
            release()

    return EvidenceResponse(stream(), release=release, media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Length": str(state["size"]), "X-Content-SHA256": state["sha256"],
            "Cache-Control": "no-store", "Content-Disposition": f'attachment; filename="event-{event_id}.pcap"'})
