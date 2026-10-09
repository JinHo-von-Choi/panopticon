"""실제 파일과 DB의 수집 대기량을 Chrome 화면까지 확인한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket

import pytest
import uvicorn
from httpx import ASGITransport, AsyncClient

from netwatcher.ingest.runtime import EveConsole
from tests.test_ingest.test_backlog import alert_line


@pytest.mark.asyncio
async def test_backlog_and_unknown_position_reach_actual_console(db, config, tmp_path, monkeypatch):
    if not shutil.which('node') or not os.environ.get('PANOPTICON_PLAYWRIGHT_CORE') or not shutil.which('google-chrome'):
        pytest.skip('Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE')
    path = tmp_path / 'eve.json'
    path.write_bytes(alert_line() * 300)
    config.raw.update({'input': {'mode': 'eve', 'eve': {'sources': [{
        'directory': tmp_path, 'sensor_id': 'fixture', 'source_id': 'office'}]}},
        'web': {'host': '127.0.0.1'}})
    console = EveConsole(config, database=db)
    collector = console.service.collectors[0]
    collector.batch_records = 1
    polled = asyncio.Event()

    async def pause_after_commit(stop):
        try:
            assert await collector.poll_once() == 1
            polled.set()
            await stop.wait()
        finally:
            collector.close()

    monkeypatch.setattr(collector, 'run', pause_after_commit)
    app = console.build_app()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(128)
    listener.setblocking(False)
    server = uvicorn.Server(uvicorn.Config(app, log_level='critical', lifespan='off'))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    child = None
    await console.service.start()
    try:
        async with asyncio.timeout(10):
            await polled.wait()
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
            for phase in ('backlog', 'unknown'):
                if phase == 'unknown':
                    path.write_bytes(b'')
                capabilities = await client.get('/api/capabilities')
                assert capabilities.status_code == 200
                assert capabilities.json()['features']['eve_observations'] is True
                response = await client.get('/api/observation')
                source = response.json()['sources'][0]
                assert source['gaps'] == source['rejected'] == 0
                assert (await client.get('/ready')).status_code == 503
                if phase == 'backlog':
                    assert source['backlog']
                    assert source['pending_bytes'] == len(alert_line()) * 299
                else:
                    assert source['pending_bytes'] is None
                fixture = tmp_path / ('browser-' + phase + '.json')
                fixture.write_text(json.dumps({'url': 'http://127.0.0.1:' + str(listener.getsockname()[1]),
                                              'phase': phase}))
                fixture.chmod(0o600)
                driver = Path(__file__).resolve().parents[1] / 'browser' / 'eve-backlog.cjs'
                child = await asyncio.create_subprocess_exec('node', str(driver), str(fixture),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                async with asyncio.timeout(45):
                    stdout, stderr = await child.communicate()
                assert child.returncode == 0, stderr.decode()[-4000:]
                assert b'EVE backlog browser checks passed' in stdout
    finally:
        if child is not None and child.returncode is None:
            child.kill()
            await child.wait()
        await console.service.stop()
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
