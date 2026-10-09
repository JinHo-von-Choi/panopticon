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
from tests.test_web.test_remote_rules import rules_api, engine_api, control, detects, document
import yaml


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["remote", "local"])
async def test_rules_browser_roles_conflict_unknown_refresh_logout(rules_api, db, config, tmp_path, mode):
    node = shutil.which("node")
    if not node or not os.environ.get("PANOPTICON_PLAYWRIGHT_CORE") or not shutil.which("google-chrome"):
        pytest.skip("Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE")
    client, header, service, registry, editor, accounts, control_server, stopped, path = rules_api
    await accounts.create("viewer", "a-strong-test-password-123", "viewer", "test")
    await SensorStateRepository(db).publish("office", service.owner, {"state": "partial"}, lease_seconds=120)
    app = client._transport.app
    path.write_text(yaml.safe_dump({"rules": [document()] + [document(f"OWNED-{index:03}", f"marker-{index}") for index in range(2, 62)]}))
    registry._find_active("signature").reload_rules()
    if mode == "local":
        app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
            auth_manager=app.state.auth_manager, signature_engine=registry._find_active("signature"),
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
        fixture = tmp_path / "rules-browser.json"
        fixture.write_text(json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password": "a-strong-test-password-123", "legacy": mode == "local"}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "remote-rules.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "rules browser checks passed" in stdout.decode()
        assert detects(registry) == "OWNED-001"
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims") == (0 if mode == "local" else 4)
        assert not stopped
    finally:
        if child is not None and child.returncode is None:
            child.kill(); await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
