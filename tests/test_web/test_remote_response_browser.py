"""실제 웹 서버와 독립 실행기를 연결한 방어 화면 회귀 검사."""

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from tests.test_web.test_remote_response import remote_case, PASSWORD


@pytest.mark.asyncio
async def test_defense_console_approval_execution_and_lost_reply(remote_case, tmp_path, db):
    playwright = os.environ.get("PANOPTICON_PLAYWRIGHT_CORE")
    chrome = os.environ.get("PANOPTICON_CHROME") or shutil.which("google-chrome")
    node = shutil.which("node")
    if not playwright or not chrome or not node:
        pytest.skip("Set PANOPTICON_PLAYWRIGHT_CORE and provide Chrome/Node for browser verification")
    case = remote_case
    await case.users.create("viewer", PASSWORD, "viewer", "admin")
    proposal = await case.client.post("/api/response-proposals", headers=case.header, json={
        "source_ip": "8.8.8.8", "visibility_state": "observed", "asset_id": "router",
        "scope_kind": "asset", "scope_asset_id": "router",
        "confirmed_at": datetime.now(timezone.utc).isoformat()})
    assert proposal.status_code == 201
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(case.app, log_level="error", lifespan="off"))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    child = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        fixture = tmp_path / "browser.json"
        fixture.write_text(json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}",
            "password": PASSWORD, "proposal": case.proposal,
            "lost_proposal": proposal.json()["proposal_id"]}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "remote-response.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            env={**os.environ, "PANOPTICON_PLAYWRIGHT_CORE": playwright, "PANOPTICON_CHROME": chrome},
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(90):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert "browser checks passed" in stdout.decode()
        # 응답 유실 후 화면은 승인 요청을 다시 보내지 않았다.
        assert await db.pool.fetchval("SELECT count(*) FROM response_execution_bindings") == 2
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
