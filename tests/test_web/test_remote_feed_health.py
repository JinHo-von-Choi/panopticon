"""실제 센서 소켓과 피드 갱신을 통해 상태 조회의 실패 경계를 검증한다."""

import json
import time
from dataclasses import replace

import pytest
import pytest_asyncio
from aiohttp import web

from netwatcher.services.sensor_control import SensorControlRequest
from netwatcher.services.sensor_blocklist import SensorBlocklist
from tests.test_web.test_remote_blocklist import blocklist_api, engine_api, control, manager


@pytest_asyncio.fixture
async def health_api(blocklist_api, monkeypatch):
    feeds = blocklist_api[-1]
    status = {'code':200, 'requests':[]}
    async def serve(request):
        status['requests'].append(request.headers.get('If-None-Match'))
        text = '203.0.113.7\n' if request.path == '/ip' else 'malware.example\n'
        code=status.get(request.path,status['code'])
        return web.Response(status=code, text=text if code==200 else None, headers={'ETag':'"owned-feed"'})
    app=web.Application();app.router.add_get('/{kind}',serve)
    runner=web.AppRunner(app);await runner.setup()
    site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
    prefix=f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}'
    import netwatcher.threatintel.feed_manager as module
    # 소유한 로컬 HTTP 피드의 양성 대조만 연결 경계를 대체한다.
    # 운영 커넥터의 내부 주소 거절은 별도 실제 소켓 시험에서 검증한다.
    monkeypatch.setattr(module, 'public_client_session', module.aiohttp.ClientSession)
    validate=module.validate_outbound_url
    monkeypatch.setattr(module,'validate_outbound_url',lambda url: url if url.startswith(prefix+'/') else validate(url))
    feeds._sources=[replace(source,url=prefix+('/ip' if source.feed_type=='ip' else '/domain')) for source in feeds._sources]
    feeds._owned_http_status=status
    try:
        assert (await feeds.update_all()).delivered==2
        yield blocklist_api
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_actual_feed_health_reads_live_source_and_keeps_last_success(db, health_api, monkeypatch):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    assert (await client.get('/api/support-profile')).status_code == 401
    before = (await client.get('/api/support-profile', headers=header)).json()['feeds']
    assert before == feeds.feed_health()
    assert before['status'] == 'ok' and before['outcomes'] == {'Owned IP feed':'downloaded', 'Owned domain feed':'downloaded'}
    timestamp = before['last_success_epoch']
    feeds.last_update_epoch = time.time() - 13 * 3600
    feeds._confirmed_epochs = {name: feeds.last_update_epoch for name in feeds._confirmed_epochs}
    stale = (await client.get('/api/support-profile', headers=header)).json()
    assert stale['feeds']['status'] == 'stale'
    assert any(v['code'] == 'SUP-060' for v in stale['violations'])
    feeds.last_update_epoch = timestamp
    feeds._confirmed_epochs = {name: timestamp for name in feeds._confirmed_epochs}
    async def fail(source, acc):
        raise ConnectionError('Owned failed download')
    monkeypatch.setattr(feeds, '_update_feed', fail)
    result = await feeds.update_all()
    assert result.succeeded is False
    after = (await client.get('/api/support-profile', headers=header)).json()['feeds']
    assert after['last_success_epoch'] == timestamp
    assert after['last_attempt']['succeeded'] is False
    assert after['last_attempt']['failed'] == 2
    assert after['blocked_ips'] == before['blocked_ips']
    assert after['blocked_domains'] == before['blocked_domains']
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims') == 0
    assert stopped == []


@pytest.mark.asyncio
@pytest.mark.parametrize('role', ['viewer','analyst'])
async def test_feed_health_roles_and_account_revocation(db, health_api, role):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    await accounts.create(role,'a-strong-test-password-123',role,'test')
    login = await client.post('/api/auth/login',json={'username':role,'password':'a-strong-test-password-123'})
    reader = {'Authorization':'Bearer '+login.json()['token']}
    assert (await client.get('/api/support-profile', headers=reader)).json()['feeds']['status'] == 'ok'
    await db.pool.execute('UPDATE user_accounts SET version=version+1 WHERE username=$1',role)
    assert (await client.get('/api/support-profile', headers=reader)).status_code == 401
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['absent','quarantine','socket','lease'])
async def test_no_manager_and_connection_failures_are_explicit(db, health_api, change):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    if change == 'absent': service.blocklist = SensorBlocklist(None)
    elif change == 'quarantine': service._blocklist_unconfirmed = True
    elif change == 'socket': await server.close()
    else: await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-interval '1 second'")
    result = await client.get('/api/support-profile', headers=header)
    assert result.status_code == 200
    health = result.json()['feeds']
    assert health['status'] == ('unconfigured' if change == 'absent' else 'unknown')
    assert health.get('blocked_ips') is None
    if change != 'absent': assert any(v['code']=='SUP-061' for v in result.json()['violations'])
    assert not stopped


@pytest.mark.asyncio
@pytest.mark.parametrize('change', ['bool_count','large_count','fresh_no_time','extra','wrong_id','unknown','bad_outcome','source_age','source_duplicate','source_extra','aggregate'])
async def test_invalid_sensor_receipts_do_not_claim_healthy(health_api, change):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    async def broken(request):
        result = await service(request)
        if request.operation == 'feeds.health':
            if change == 'bool_count': result['feeds']['blocked_ips'] = True
            elif change == 'large_count': result['feeds']['blocked_ips'] = 2**1000
            elif change == 'fresh_no_time': result['feeds']['age_hours'] = None
            elif change == 'extra': result['feeds']['url'] = 'private source location'
            elif change == 'wrong_id': result['request_id'] = 'unrelated'
            elif change == 'unknown': return {'status':'unknown','request_id':request.request_id}
            elif change=='bad_outcome': result['feeds']['outcomes'] = {'owned':'unrecognized'}
            elif change=='source_age': result['feeds']['sources'][0]['age_hours']=True
            elif change=='source_duplicate': result['feeds']['sources'][1]=dict(result['feeds']['sources'][0])
            elif change=='source_extra': result['feeds']['sources'][0]['url']='private source location'
            else: result['feeds']['status']='degraded'
        return result
    server.handler = broken
    result = await client.get('/api/support-profile', headers=header)
    assert result.json()['feeds']['status'] == 'unknown'
    assert 'private source location' not in result.text
    assert not stopped


@pytest.mark.asyncio
async def test_feed_read_refuses_mutation_fields(control):
    service, registry, editor, request, send, stopped, accounts, server = control
    for changes in ({'engine':'port_scan'}, {'updates':{'enabled':True}}, {'base_version':'a'*64}):
        value = json.loads(request('whitelist.read',engine='whitelist').to_bytes())
        value.update({'operation':'feeds.health','engine':'feeds', **changes})
        with pytest.raises(ValueError): SensorControlRequest.from_bytes(json.dumps(value).encode())


@pytest.mark.asyncio
async def test_actual_http_failure_with_cached_content_does_not_refresh_clock(health_api):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    previous=time.time()-13*3600
    feeds.last_update_epoch=previous
    feeds._confirmed_epochs = {name: previous for name in feeds._confirmed_epochs}
    feeds._owned_http_status['code']=503
    result=await feeds.update_all()
    assert result.succeeded and result.from_cache==2 and result.delivered==0
    assert feeds.last_update_epoch==previous
    response=await client.get('/api/support-profile',headers=header)
    health=response.json()['feeds']
    assert health['status']=='stale' and health['last_success_epoch']==previous
    assert health['blocked_ips']==1 and health['blocked_domains']==1
    assert not stopped


@pytest.mark.asyncio
async def test_actual_conditional_http_304_confirms_cache_freshness(health_api):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    previous=time.time()-13*3600
    feeds.last_update_epoch=previous
    feeds._confirmed_epochs = {name: previous for name in feeds._confirmed_epochs}
    feeds._owned_http_status.update({'code':304,'requests':[]})
    result=await feeds.update_all()
    assert result.succeeded and result.from_cache==2 and result.delivered==0
    assert feeds._owned_http_status['requests']==['"owned-feed"','"owned-feed"']
    assert feeds.last_update_epoch>previous
    health=(await client.get('/api/support-profile',headers=header)).json()['feeds']
    assert health['status']=='ok' and health['last_success_epoch']==feeds.last_update_epoch
    assert not stopped


@pytest.mark.asyncio
async def test_one_success_does_not_hide_stale_cached_source(health_api):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    previous=time.time()-13*3600
    feeds._confirmed_epochs={source.name:previous for source in feeds._sources}
    feeds.last_update_epoch=previous
    feeds._owned_http_status['/domain']=503
    result=await feeds.update_all()
    assert result.delivered==1 and result.from_cache==1
    response=await client.get('/api/support-profile',headers=header)
    assert response.status_code==200
    health=response.json()['feeds']
    assert health['status']=='degraded' and health['age_hours']==0
    sources={source['name']:source for source in health['sources']}
    assert sources['Owned IP feed']['status']=='ok'
    assert sources['Owned domain feed']['status']=='stale'
    assert sources['Owned domain feed']['last_success_epoch']==previous
    assert sources['Owned domain feed']['outcome']=='cached'
    assert any(item['code']=='SUP-060' for item in response.json()['violations'])
    assert feeds.is_stale() and feeds.health_as_violations()


@pytest.mark.asyncio
async def test_unconfirmed_cache_after_restart_keeps_source_time_unknown(health_api):
    client, header, service, registry, editor, accounts, server, stopped, feeds = health_api
    from netwatcher.threatintel.feed_manager import FeedManager
    restarted=FeedManager(feeds._config)
    restarted._sources=list(feeds._sources)
    service.blocklist=SensorBlocklist(restarted)
    registry.set_feeds(restarted)
    feeds._owned_http_status['code']=503
    assert (await restarted.update_all()).from_cache==2
    assert restarted.last_update_epoch==0 and not restarted._confirmed_epochs
    health=(await client.get('/api/support-profile',headers=header)).json()['feeds']
    assert health['status']=='stale'
    assert all(source['status']=='unknown' and source['last_success_epoch'] is None for source in health['sources'])
