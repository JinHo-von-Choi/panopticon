"""실제 Chrome에서 센서 피드 상태와 연결 실패를 구분한다."""

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import time
from dataclasses import replace

import pytest
import uvicorn

from netwatcher.services.sensor_blocklist import SensorBlocklist
from tests.test_web.test_remote_blocklist import blocklist_api, engine_api, control, manager
from tests.test_web.test_remote_feed_health import health_api


@pytest.mark.asyncio
async def test_actual_feed_health_browser_fresh_stale_unconfigured_and_disconnected(health_api, tmp_path):
    node = shutil.which('node')
    if not node or not os.environ.get('PANOPTICON_PLAYWRIGHT_CORE') or not shutil.which('google-chrome'):
        pytest.skip('Provide Chrome/Node and PANOPTICON_PLAYWRIGHT_CORE')
    client, header, service, registry, editor, accounts, sensor, stopped, feeds = health_api
    await accounts.create('feed-viewer','a-strong-test-password-123','viewer','test')
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(128);listener.setblocking(False)
    server=uvicorn.Server(uvicorn.Config(client._transport.app,log_level='critical',lifespan='off'))
    task=asyncio.create_task(server.serve(sockets=[listener])); child=None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                assert not task.done()
                await asyncio.sleep(.02)
        for phase in ('ok','stale','degraded','escape','unconfigured','unknown'):
            if phase=='stale':
                feeds.last_update_epoch=time.time()-13*3600
                feeds._confirmed_epochs={name:feeds.last_update_epoch for name in feeds._confirmed_epochs}
            elif phase=='degraded':
                feeds._owned_http_status['/domain']=503
                assert (await feeds.update_all()).delivered==1
            elif phase=='escape':
                feeds._owned_http_status.pop('/domain')
                feeds._sources[0]=replace(feeds._sources[0],name='<img src=x onerror=window.feedInjected=1>')
                assert (await feeds.update_all()).delivered==2
            elif phase=='unconfigured': service.blocklist=SensorBlocklist(None)
            elif phase=='unknown': await sensor.close()
            fixture=tmp_path/f'feeds-{phase}.json'
            fixture.write_text(json.dumps({'url':f'http://127.0.0.1:{listener.getsockname()[1]}',
                'password':'a-strong-test-password-123','phase':phase}));fixture.chmod(0o600)
            driver=Path(__file__).resolve().parents[1]/'browser'/'remote-feed-health.cjs'
            child=await asyncio.create_subprocess_exec(node,str(driver),str(fixture),
                stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
            async with asyncio.timeout(45): stdout,stderr=await child.communicate()
            assert child.returncode==0,stderr.decode()[-2000:]
            assert 'feed health browser checks passed' in stdout.decode()
        assert not stopped
    finally:
        if child is not None and child.returncode is None:
            child.kill();await child.wait()
        server.should_exit=True
        await asyncio.wait_for(task,5);listener.close()
