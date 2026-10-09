"""실제 Chrome에서 분리·통합 콘솔의 규칙 변경을 검증한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from netwatcher.alerts.stream import EventStream
from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository
from netwatcher.storage.sensor_state import SensorStateRepository
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from tests.test_web.test_remote_evidence import evidence_api, engine_api, control


@pytest.mark.asyncio
async def test_evidence_browser_download_pin_conflict_unknown_and_roles(evidence_api, db, tmp_path):
    node = shutil.which("node")
    if not node or not os.environ.get("PANOPTICON_PLAYWRIGHT_CORE") or not shutil.which("google-chrome"):
        pytest.skip("Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE")
    client, header, service, registry, editor, accounts, control_server, stopped, writer, event_id, path = evidence_api
    await accounts.create("viewer", "a-strong-test-password-123", "viewer", "test")
    await SensorStateRepository(db).publish("office", service.owner, {"state": "partial"}, lease_seconds=120)
    app = client._transport.app
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0)); listener.listen(128); listener.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    child = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        fixture = tmp_path / "evidence-browser.json"
        fixture.write_text(json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password": "a-strong-test-password-123", "event_id": event_id, "sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest()}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "remote-evidence.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "evidence browser checks passed" in stdout.decode()
        assert writer.evidence_availability(event_id)["pin_state"] == "unpinned"
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 4
        assert not stopped
    finally:
        if child is not None and child.returncode is None:
            child.kill(); await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
