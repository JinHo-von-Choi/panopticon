"""실제 웹·센서·DB와 Chrome에서 위협 지표 화면을 확인한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from netwatcher.storage.sensor_state import SensorStateRepository
from netwatcher.storage.repositories import BlocklistRepository, DeviceRepository, EventRepository, TrafficStatsRepository
from netwatcher.alerts.stream import EventStream
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from tests.test_web.test_remote_blocklist import blocklist_api, engine_api, control, manager


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["remote", "local"])
async def test_blocklist_browser_roles_conflict_lost_reply_logout(blocklist_api, db, config, tmp_path, mode):
    node = shutil.which("node")
    chrome = os.environ.get("PANOPTICON_CHROME") or shutil.which("google-chrome")
    if not node or not chrome or not os.environ.get("PANOPTICON_PLAYWRIGHT_CORE"):
        pytest.skip("Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE")
    client, header, service, registry, editor, accounts, control_server, stopped, feed = blocklist_api
    await accounts.create("viewer", "a-strong-test-password-123", "viewer", "test")
    await SensorStateRepository(db).publish("office", service.owner, {"state":"partial"}, lease_seconds=120)
    app = client._transport.app
    if mode == "local":
        app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
            auth_manager=app.state.auth_manager, blocklist_repo=BlocklistRepository(db), feed_manager=feed,
            audit_logger=AuditLogger(db.pool), audit_required=True)
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
        fixture = tmp_path / "blocklist-browser.json"
        fixture.write_text(json.dumps({"url":f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password":"a-strong-test-password-123", "legacy":mode == "local"}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "remote-blocklist.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "blocklist browser checks passed" in stdout.decode()
        assert await db.pool.fetchval("SELECT count(*) FROM custom_blocklist") == 1
        assert await db.pool.fetchval("SELECT value FROM custom_blocklist") == "198.51.100.44"
        assert feed.match_ip("198.51.100.44")["source"] == "Custom"
        assert feed.match_ip("198.51.100.9") is None
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == (0 if mode == "local" else 3)
        assert stopped == []
    finally:
        if child is not None and child.returncode is None:
            child.kill(); await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
