"""실제 웹 서버·DB·센서 Unix 소켓의 엔진 화면 검사."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from netwatcher.storage.sensor_state import SensorStateRepository
from tests.test_web.test_remote_engines import engine_api, control


@pytest.mark.asyncio
async def test_engine_console_versions_unknown_results_roles_and_session(engine_api, db, tmp_path):
    playwright = os.environ.get("PANOPTICON_PLAYWRIGHT_CORE")
    chrome = os.environ.get("PANOPTICON_CHROME") or shutil.which("google-chrome")
    node = shutil.which("node")
    if not playwright or not chrome or not node:
        pytest.skip("Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE for browser verification")
    client, header, service, registry, editor, accounts, control_server, stopped = engine_api
    await accounts.create("viewer", "a-strong-test-password-123", "viewer", "test")
    await SensorStateRepository(db).publish("office", service.owner, {"state": "partial"}, lease_seconds=120)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(client._transport.app, log_level="error", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    child = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        fixture = tmp_path / "engine-browser.json"
        fixture.write_text(json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password": "a-strong-test-password-123"}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "remote-engines.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "engine browser checks passed" in stdout.decode()
        assert editor.get_engine_config("port_scan")["threshold"] == 25
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_control_claims WHERE status='completed'") == 4
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
