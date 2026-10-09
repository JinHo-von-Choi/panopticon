"""Chrome의 제안 작성·비교·승인과 권한·미확정 복구를 검증한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
from uuid import uuid4

import pytest
import uvicorn

from netwatcher.alerts.stream import EventStream
from netwatcher.services.remote_sensor_control import RemoteSensorControl
from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository
from netwatcher.storage.sensor_state import SensorStateRepository
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from tests.test_web.test_remote_proposals import proposals_api, engine_api, control
from tests.test_services.test_sensor_ai_proposals import bound_analyzer


@pytest.mark.asyncio
async def test_remote_ai_browser_status_logs_failure_and_session(db, config, proposals_api, tmp_path):
    node = shutil.which('node')
    if not node or not os.environ.get('PANOPTICON_PLAYWRIGHT_CORE') or not shutil.which('google-chrome'):
        pytest.skip('Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE')
    client, header, service, registry, editor, accounts, socket_server, stopped, replay = proposals_api
    for role in ('viewer', 'analyst'):
        await accounts.create(role, 'a-strong-test-password-123', role, 'test')
    await SensorStateRepository(db).publish('office', service.owner, {'state':'partial'}, lease_seconds=120)
    remote = RemoteSensorControl(db, 'office', socket_server.path, expected_uid=os.getuid())
    analyzer, _ = bound_analyzer(db, config, proposals_api)
    service.ai_analyzer = analyzer
    for index in range(51):
        await EventRepository(db).insert('ai_analyzer','INFO','AI 불확실',
            description='<img src=x onerror=window.aiInjected=1> record '+str(index),
            metadata={'verdict':'UNCERTAIN','provider':'copilot','original_engine':'port_scan'})
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
        auth_manager=client._transport.app.state.auth_manager, sensor_control=remote, replay_service=replay,
        audit_logger=AuditLogger(db.pool), audit_required=True)
    listener = socket.socket();listener.bind(('127.0.0.1',0));listener.listen(128);listener.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(app,log_level='error',lifespan='off'))
    task = asyncio.create_task(server.serve(sockets=[listener]));child = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done();await asyncio.sleep(.02)
        fixture = tmp_path/'ai-browser.json'
        fixture.write_text(json.dumps({'url':f'http://127.0.0.1:{listener.getsockname()[1]}',
            'password':'a-strong-test-password-123','screenshot':str(tmp_path/'ai-console.png')}))
        fixture.chmod(0o600)
        driver = Path(__file__).resolve().parents[1]/'browser'/'remote-ai.cjs'
        child = await asyncio.create_subprocess_exec(node,str(driver),str(fixture),stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        async with asyncio.timeout(100):
            stdout,stderr=await child.communicate()
        assert child.returncode==0,stderr.decode()[-3000:]
        assert 'ai browser checks passed' in stdout.decode()
        assert await db.pool.fetchval('SELECT count(*) FROM config_proposals') == 0
        assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims') == 0
        assert not stopped
    finally:
        if child is not None and child.returncode is None:
            child.kill();await child.wait()
        await analyzer.stop()
        server.should_exit=True;await asyncio.wait_for(task,5);listener.close()
