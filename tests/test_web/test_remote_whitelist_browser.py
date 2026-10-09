"""실제 웹·DB·센서 소켓으로 탐지 예외 화면을 검증한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from netwatcher.storage.sensor_state import SensorStateRepository
from netwatcher.storage.repositories import DeviceRepository, EventRepository
from netwatcher.storage.repositories import TrafficStatsRepository
from netwatcher.alerts.stream import EventStream
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from tests.test_web.test_remote_engines import engine_api, control


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["remote", "local"])
async def test_whitelist_console_shared_state_roles_unknown_and_logout(engine_api, db, config, tmp_path, mode):
    node = shutil.which("node")
    chrome = os.environ.get("PANOPTICON_CHROME") or shutil.which("google-chrome")
    if not node or not chrome or not os.environ.get("PANOPTICON_PLAYWRIGHT_CORE"):
        pytest.skip("Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE")
    client, header, service, registry, editor, accounts, control_server, stopped = engine_api
    await accounts.create("viewer", "a-strong-test-password-123", "viewer", "test")
    await SensorStateRepository(db).publish("office", service.owner, {"state":"partial"}, lease_seconds=120)
    await DeviceRepository(db).upsert("02:00:00:00:00:91", "192.0.2.94")
    event_id = await EventRepository(db).insert("port_scan", "WARNING", "Whitelist investigation test", source_ip="192.0.2.94")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)
    app = client._transport.app
    if mode == "local":
        app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
            auth_manager=app.state.auth_manager, whitelist=registry.whitelist, yaml_editor=editor,
            audit_logger=AuditLogger(db.pool), audit_required=True)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    child = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        fixture = tmp_path / "whitelist-browser.json"
        fixture.write_text(json.dumps({"url":f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password":"a-strong-test-password-123", "event_id":event_id, "legacy":mode == "local"}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "remote-whitelist.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "whitelist browser checks passed" in stdout.decode()
        if mode == "local":
            assert registry.whitelist.to_dict() == {"ips":[], "ip_ranges":[], "macs":[], "domains":[],
                                                  "domain_suffixes":[".internal", ".local"]}
            assert editor.get_whitelist_config() == registry.whitelist.to_dict()
            assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == 0
            assert not stopped
            return
        assert registry.whitelist.is_ip_whitelisted("192.0.2.92")
        assert registry.whitelist.is_ip_whitelisted("192.0.2.94")
        assert not registry.whitelist.is_ip_whitelisted("192.0.2.91")
        assert not registry.whitelist.is_ip_whitelisted("192.0.2.93")
        assert registry.whitelist.is_mac_whitelisted("02:00:00:00:00:91")
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 5
        assert not stopped
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
