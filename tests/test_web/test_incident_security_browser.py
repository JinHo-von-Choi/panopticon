"""사건 저장소 전용 콘솔의 실제 브라우저·HTTP·DB 동작."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from tests.test_web.test_incident_security import incident_api


@pytest.mark.asyncio
async def test_incident_roles_unknown_results_and_logout(incident_api, db, tmp_path):
    if not os.environ.get("PANOPTICON_PLAYWRIGHT_CORE") or not os.environ.get("PANOPTICON_CHROME") or not shutil.which("node"):
        pytest.skip("Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE for browser verification")
    client, header, repository, accounts, audit, primary, app = incident_api
    await accounts.create("viewer", "a-strong-test-password-123", "viewer", "test")
    secondary = await repository.insert("WARNING", "Second investigation")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    child = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        fixture = tmp_path / "incident-browser.json"
        fixture.write_text(json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password": "a-strong-test-password-123", "primary": primary, "secondary": secondary}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "incidents.cjs"
        child = await asyncio.create_subprocess_exec("node", str(driver), str(fixture),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "incident browser checks passed" in stdout.decode()
        assert (await repository.get_by_id(primary))["resolved"] is True
        assert (await repository.get_by_id(secondary))["resolved"] is True
        assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='api_mutation' AND resource LIKE '/api/incidents/%'") == 2
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
