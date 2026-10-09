"""DB 커밋 경보와 연결 손실 재조회를 실제 브라우저에서 확인한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn

from netwatcher.alerts.database_stream import DatabaseEventStream
from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository, ResponseActionRepository, ResponseProposalRepository
from netwatcher.web.server import create_app
from netwatcher.web.audit_log import AuditLogger
from tests.test_web.test_remote_response import remote_case, PASSWORD


@pytest.mark.asyncio
async def test_real_browser_receives_committed_alerts_and_refreshes_after_gap(remote_case, db, config, tmp_path):
    playwright = os.environ.get("PANOPTICON_PLAYWRIGHT_CORE")
    chrome = os.environ.get("PANOPTICON_CHROME") or shutil.which("google-chrome")
    node = shutil.which("node")
    if not playwright or not chrome or not node:
        pytest.skip("Set PANOPTICON_PLAYWRIGHT_CORE and provide Chrome/Node for browser verification")
    stream = DatabaseEventStream(db)
    await stream.start()
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), stream,
        auth_manager=remote_case.manager, audit_logger=AuditLogger(db.pool), audit_required=True,
        response_repository=ResponseActionRepository(db), response_proposal_repo=ResponseProposalRepository(db))
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
        fixture = tmp_path / "browser.json"
        fixture.write_text(json.dumps({"url": f"http://127.0.0.1:{listener.getsockname()[1]}", "password": PASSWORD}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1] / "browser" / "database-stream.cjs"
        child = await asyncio.create_subprocess_exec(node, str(driver), str(fixture),
            env={**os.environ, "PANOPTICON_PLAYWRIGHT_CORE": playwright, "PANOPTICON_CHROME": chrome},
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(30):
            assert await child.stdout.readline() == b"READY\n"
            async with db.pool.acquire() as conn:
                transaction = conn.transaction()
                await transaction.start()
                try:
                    await conn.execute("INSERT INTO events(engine,severity,title) VALUES('port_scan','WARNING','늦은 커밋 경보')")
                    await db.pool.execute("INSERT INTO events(engine,severity,title) VALUES('port_scan','WARNING','먼저 커밋 경보')")
                    assert await child.stdout.readline() == b"FIRST\n"
                    await transaction.commit()
                except BaseException:
                    if conn.is_in_transaction():
                        await transaction.rollback()
                    raise
            assert await child.stdout.readline() == b"SECOND\n"
            pid = await stream._connection.fetchval("SELECT pg_backend_pid()")
            assert await db.pool.fetchval("SELECT pg_terminate_backend($1)", pid)
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-3000:]
        assert b"browser stream checks passed" in stdout
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 2
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
        await stream.stop()
