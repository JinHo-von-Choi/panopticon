"""실제 AI 수명·HTTP·계정·Unix 소켓·DB 소유권으로 상태 조회를 검증한다."""

import asyncio
from pathlib import Path
from uuid import uuid4

import pytest

from netwatcher.services.sensor_control import SensorControlRequest
from tests.test_services.test_sensor_ai_proposals import bound_analyzer
from tests.test_web.test_remote_proposals import proposals_api, engine_api, control, login


@pytest.mark.asyncio
async def test_real_ai_lifecycle_and_viewer_status_do_not_mutate(db, config, proposals_api):
    client, admin, service, registry, editor, accounts, server, stopped, replay = proposals_api
    viewer = await login(client, accounts, 'viewer')
    assert (await client.get('/api/ai-analyzer/status')).status_code == 401
    response = await client.get('/api/ai-analyzer/status', headers=viewer)
    assert response.status_code == 200
    assert response.json()['state'] == 'unconfigured'
    assert response.json()['interval_minutes'] is None
    analyzer, _ = bound_analyzer(db, config, proposals_api)
    service.ai_analyzer = analyzer
    original = Path(editor._path).read_bytes()
    before = (await client.get('/api/ai-analyzer/status', headers=viewer)).json()
    assert before['enabled'] and not before['running'] and before['state'] == 'stopped'
    # 빈 실제 DB로 시작하므로 외부 모델에 보낼 분석 대상이 없다.
    assert await db.pool.fetchval('SELECT count(*) FROM events') == 0
    await analyzer.start()
    try:
        await asyncio.sleep(0)
        running = await client.get('/api/ai-analyzer/status', headers=viewer)
        assert running.status_code == 200
        assert running.json()['state'] == 'running' and running.json()['running'] is True
    finally:
        await analyzer.stop()
    after = await client.get('/api/ai-analyzer/status', headers=viewer)
    assert after.status_code == 200 and after.json()['state'] == 'stopped'
    assert Path(editor._path).read_bytes() == original and not stopped
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims') == 0
    assert await db.pool.fetchval('SELECT count(*) FROM config_proposals') == 0


@pytest.mark.asyncio
async def test_ai_status_disconnect_bad_receipt_and_expired_lease_are_unavailable(db, engine_api):
    client, header, service, registry, editor, accounts, server, stopped = engine_api
    async def corrupt(command):
        result = await service(command)
        if command.operation == 'ai.status':
            result['ai']['running'] = True
        return result
    server.handler = corrupt
    response = await client.get('/api/ai-analyzer/status', headers=header)
    assert response.status_code == 503
    assert 'enabled' not in response.json()
    server.handler = service
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
    assert (await client.get('/api/ai-analyzer/status', headers=header)).status_code == 503
    await server.close()
    assert (await client.get('/api/ai-analyzer/status', headers=header)).status_code == 503


@pytest.mark.parametrize('engine,updates', [('port_scan', {}), ('ai', {'enabled': True})])
def test_ai_read_protocol_rejects_resource_confusion_and_updates(engine, updates):
    import json
    value = {'request_id':str(uuid4()), 'sensor_id':'office', 'owner':str(uuid4()),
             'actor_id':str(uuid4()), 'actor_version':1, 'operation':'ai.status',
             'engine':engine, 'base_version':'', 'updates':updates}
    with pytest.raises(ValueError):
        SensorControlRequest.from_bytes(json.dumps(value).encode())
