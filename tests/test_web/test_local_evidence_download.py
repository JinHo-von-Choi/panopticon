"""통합 콘솔의 실제 PCAP 파일과 HTTP 스트림 경계를 검증한다."""

import asyncio
import hashlib
import os
import socket

import httpx
import pytest
import pytest_asyncio
import uvicorn

from netwatcher.alerts.stream import EventStream
from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.local_evidence import LocalEvidenceReader
from netwatcher.web.server import create_app
from tests.test_web.test_remote_evidence import evidence_api, engine_api, control


@pytest_asyncio.fixture
async def local_evidence(evidence_api, db, config):
    client, header, service, registry, editor, accounts, server, stopped, writer, event_id, path = evidence_api
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
        auth_manager=client._transport.app.state.auth_manager, pcap_writer=writer,
        audit_logger=AuditLogger(db.pool), audit_required=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as local:
        yield local, header, event_id, path, writer, accounts


@pytest.mark.asyncio
async def test_local_download_uses_stored_record_and_safe_headers(local_evidence, db):
    client, header, event_id, path, writer, accounts = local_evidence
    endpoint = f"/api/events/{event_id}/evidence/file"
    assert (await client.get(endpoint)).status_code == 401
    result = await client.get(endpoint, headers=header)
    assert result.status_code == 200
    assert result.content == path.read_bytes()
    assert result.headers["x-content-sha256"] == hashlib.sha256(result.content).hexdigest()
    assert result.headers["content-length"] == str(len(result.content))
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["content-disposition"] == f'attachment; filename="event-{event_id}.pcap"'
    assert str(path) not in str(result.headers)
    assert (await client.get("/api/events/999999/evidence/file", headers=header)).status_code == 404
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0


@pytest.mark.asyncio
async def test_local_pin_validation_error_returns_safe_message(local_evidence):
    client, header, event_id, path, writer, accounts = local_evidence
    writer._pins_valid = False
    result = await client.post(f"/api/events/{event_id}/evidence/pin", headers=header,
        json={"hours":24,"reason":"사건 자료 보존"})
    assert result.status_code == 409
    assert result.json()["detail"] == "증거 보존 상태 또는 보존 예산을 확인하세요."
    assert "Evidence pin state unavailable" not in result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["checksum", "symlink", "hardlink", "directory", "oversize", "short", "deleted"])
async def test_local_download_refuses_invalid_files(local_evidence, tmp_path, change):
    client, header, event_id, path, writer, accounts = local_evidence
    if change == "checksum": path.write_bytes(path.read_bytes()[:-1] + b"x")
    elif change == "hardlink": os.link(path, tmp_path / "extra.pcap")
    elif change == "symlink":
        outside = tmp_path / "outside.pcap"; path.replace(outside); path.symlink_to(outside)
    elif change == "directory": path.unlink(); path.mkdir()
    elif change == "oversize":
        with path.open("r+b") as file: file.truncate(32 * 1024 * 1024 + 1)
    elif change == "short": path.write_bytes(b"invalid")
    else: path.unlink()
    result = await client.get(f"/api/events/{event_id}/evidence/file", headers=header)
    assert result.status_code in (404, 503)
    assert "x-content-sha256" not in result.headers
    assert str(path) not in result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["account", "file"])
async def test_local_actual_http_rejects_midstream_change_and_recovers_slots(local_evidence, db, monkeypatch, change):
    client, header, event_id, path, writer, accounts = local_evidence
    original = path.read_bytes()
    chunk = LocalEvidenceReader.chunk
    changed = False

    async def mutate(self, target, version, offset):
        nonlocal changed
        value = await chunk(self, target, version, offset)
        if offset == 0 and not changed:
            changed = True
            if change == "account":
                await db.pool.execute("UPDATE user_accounts SET version=version+1 WHERE username='control-admin'")
            else:
                path.write_bytes(original[:-1] + b"x")
        return value

    monkeypatch.setattr(LocalEvidenceReader, "chunk", mutate)
    listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(128); listener.setblocking(False)
    web = uvicorn.Server(uvicorn.Config(client._transport.app, log_level="critical", lifespan="off"))
    task = asyncio.create_task(web.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not web.started:
                assert not task.done()
                await asyncio.sleep(.01)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{listener.getsockname()[1]}", timeout=10) as live:
            with pytest.raises(httpx.RemoteProtocolError):
                await live.get(f"/api/events/{event_id}/evidence/file", headers=header)
            monkeypatch.setattr(LocalEvidenceReader, "chunk", chunk)
            if change == "file": path.write_bytes(original)
            login = await live.post("/api/auth/login", json={"username":"control-admin","password":"a-strong-test-password-123"})
            assert login.status_code == 200
            fresh = {"Authorization": "Bearer " + login.json()["token"]}
            for _ in range(3):
                result = await live.get(f"/api/events/{event_id}/evidence/file", headers=fresh)
                assert result.status_code == 200 and result.content == original
        assert changed
    finally:
        web.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
