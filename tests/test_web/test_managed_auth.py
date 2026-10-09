"""관리 계정의 실제 로그인과 기존 토큰의 권한 폐기를 검증한다."""
import secrets
import asyncio
import socket
from datetime import datetime,timedelta,timezone

import bcrypt
import jwt
import pytest
import pytest_asyncio
import uvicorn
import websockets
from websockets.exceptions import ConnectionClosed
from fastapi import FastAPI
from httpx import ASGITransport,AsyncClient

from tests.test_web.test_business_reviews import review_case
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.storage.repositories import EventRepository,DeviceRepository,TrafficStatsRepository
from netwatcher.alerts.stream import EventStream
from netwatcher.web.auth import AuthManager
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from netwatcher.web.routes.events import create_ws_router

PASSWORD='ManagedFixturePassword-2026'


@pytest_asyncio.fixture
async def managed_case(db,config,review_case,monkeypatch):
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    config.raw['auth']={'enabled':True,'multi_user':True,'username':'admin',
        'password':bcrypt.hashpw(PASSWORD.encode(),bcrypt.gensalt(rounds=4)).decode(),
        'jwt_secret':secrets.token_hex(32),'api_rate_limit':{'enabled':False},'login_attempts_per_minute':1000}
    users=UserAccounts(db);manager=AuthManager(config,users=users)
    await manager.initialize()
    app=create_app(config,EventRepository(db),DeviceRepository(db),TrafficStatsRepository(db),EventStream(),
        auth_manager=manager,audit_logger=AuditLogger(db.pool),audit_required=True)
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        yield client,manager,users


async def login(client,name='admin',password=PASSWORD):
    response=await client.post('/api/auth/login',json={'username':name,'password':password})
    assert response.status_code==200,response.text
    return response.json()['token']


@pytest.mark.asyncio
async def test_bootstrap_is_once_and_managed_tokens_require_database(managed_case,db):
    client,manager,users=managed_case
    token=await login(client)
    payload=await manager.verify_token_async(token)
    assert payload['sub']=='admin' and payload['role']=='admin' and payload['ver']==1
    assert manager.verify_token(token) is None
    assert (await client.get('/api/events',headers={'Authorization':'Bearer '+token})).status_code==200
    await manager.initialize()
    assert await db.pool.fetchval('SELECT count(*) FROM user_accounts')==1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='account_bootstrap'")==1


@pytest.mark.asyncio
async def test_role_change_revokes_old_token_and_next_login_has_new_role(managed_case):
    client,manager,users=managed_case
    token=await login(client)
    admin=(await users.list())['users'][0]
    await users.create('other-admin',PASSWORD,'admin','admin')
    await users.update(admin['id'],1,role='viewer',enabled=True,actor='other-admin')
    for path in ('/api/events','/api/auth/status'):
        assert (await client.get(path,headers={'Authorization':'Bearer '+token})).status_code==401
    new=await login(client)
    assert (await manager.verify_token_async(new))['role']=='viewer'
    assert (await client.get('/api/events',headers={'Authorization':'Bearer '+new})).status_code==200
    event=(await client.get('/api/events',headers={'Authorization':'Bearer '+new})).json()['events'][0]
    denied=await client.put(f"/api/events/{event['id']}/case",headers={'Authorization':'Bearer '+new},json={
        'expected_version':0,'owner':'viewer','status':'closed','note':'viewer must not change case'})
    assert denied.status_code==403


@pytest.mark.asyncio
async def test_disable_and_password_reset_revoke_previous_sessions(managed_case):
    client,manager,users=managed_case
    member=await users.create('member',PASSWORD,'analyst','admin')
    token=await login(client,'member')
    disabled=await users.update(member['id'],1,role='analyst',enabled=False,actor='admin')
    assert await manager.verify_token_async(token) is None
    assert (await client.post('/api/auth/login',json={'username':'member','password':PASSWORD})).status_code==401
    enabled=await users.update(member['id'],disabled['version'],role='analyst',enabled=True,actor='admin')
    token=await login(client,'member')
    new_password='ChangedFixturePassword-2026'
    await users.reset_password(member['id'],enabled['version'],new_password,'admin')
    assert await manager.verify_token_async(token) is None
    assert (await client.post('/api/auth/login',json={'username':'member','password':PASSWORD})).status_code==401
    assert await manager.verify_token_async(await login(client,'member',new_password)) is not None


@pytest.mark.asyncio
async def test_signed_legacy_and_wrong_managed_claims_are_rejected(managed_case):
    client,manager,users=managed_case
    token=await login(client);payload=jwt.decode(token,manager._secret,algorithms=['HS256'])
    for change in ({'ver':True},{'uid':'invalid'},{'role':'owner'},{'sub':'somebody'}):
        bad=jwt.encode(payload|change,manager._secret,algorithm='HS256')
        assert await manager.verify_token_async(bad) is None
    for key in ('exp','iat','sub','uid','ver','role'):
        incomplete=payload.copy();incomplete.pop(key)
        assert await manager.verify_token_async(jwt.encode(incomplete,manager._secret,algorithm='HS256')) is None
    legacy=jwt.encode({'sub':'admin','role':'admin','exp':datetime.now(timezone.utc)+timedelta(hours=1)},manager._secret,algorithm='HS256')
    assert await manager.verify_token_async(legacy) is None


@pytest.mark.asyncio
async def test_database_failure_is_unavailable_not_authenticated(managed_case,db):
    client,manager,users=managed_case
    token=await login(client)
    await db.pool.execute('ALTER TABLE user_accounts RENAME TO unavailable_accounts')
    try:
        headers={'Authorization':'Bearer '+token}
        assert (await client.get('/api/events',headers=headers)).status_code==503
        assert (await client.get('/api/auth/status',headers=headers)).status_code==503
        assert (await client.post('/api/auth/login',json={'username':'admin','password':PASSWORD})).status_code==503
    finally:await db.pool.execute('ALTER TABLE unavailable_accounts RENAME TO user_accounts')


@pytest.mark.asyncio
async def test_eve_startup_bootstraps_once_and_preserves_changed_credentials(db,config,tmp_path,monkeypatch):
    from netwatcher.ingest.runtime import EveConsole
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    config.raw.update({'input':{'mode':'eve','eve':{'sources':[{
        'directory':str(tmp_path),'sensor_id':'managed-sensor','source_id':'office'}]}},
        'web':{'host':'127.0.0.1'},'auth':{'enabled':True,'multi_user':True,'username':'admin',
        'password':bcrypt.hashpw(PASSWORD.encode(),bcrypt.gensalt(rounds=4)).decode(),
        'jwt_secret':secrets.token_hex(32),'api_rate_limit':{'enabled':False}}})
    app=EveConsole(config,database=db).build_app()
    assert await db.pool.fetchval('SELECT count(*) FROM user_accounts')==0
    async with app.router.lifespan_context(app):
        manager=app.state.auth_manager
        original=await manager.authenticate_async('admin',PASSWORD)
        assert original
        users=manager.users;account=(await users.list())['users'][0]
        await users.reset_password(account['id'],1,'RestartReplacementPassword-2026','admin')
    restarted=EveConsole(config,database=db).build_app()
    async with restarted.router.lifespan_context(restarted):
        manager=restarted.state.auth_manager
        assert await manager.authenticate_async('admin',PASSWORD) is None
        assert await manager.authenticate_async('admin','RestartReplacementPassword-2026')
        assert await manager.verify_token_async(original) is None
        assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='account_bootstrap'")==1


@pytest.mark.asyncio
@pytest.mark.parametrize('change,idle,expected_code', [
    ('disable',False,1008), ('role',False,1008), ('password',False,1008),
    ('disable',True,1008), ('database',False,1013)])
async def test_live_stream_revokes_session_before_next_event(managed_case,db,change,idle,expected_code):
    client,manager,users=managed_case
    member=await users.create('stream-member',PASSWORD,'analyst','admin')
    token=await login(client,'stream-member')
    stream=EventStream()
    app=FastAPI()
    app.include_router(create_ws_router(stream,manager),prefix='/api')
    listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
    port=listener.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,log_level='critical',lifespan='off',timeout_graceful_shutdown=1))
    task=asyncio.create_task(server.serve(sockets=[listener]))
    renamed=False
    try:
        async with asyncio.timeout(3):
            while not server.started:await asyncio.sleep(.01)
        async with websockets.connect(f'ws://127.0.0.1:{port}/api/ws/events?token={token}') as ws:
            stream.publish({'type':'alert','title':'before account change'})
            assert 'before account change' in await asyncio.wait_for(ws.recv(),2)
            if change=='disable':
                await users.update(member['id'],1,role='analyst',enabled=False,actor='admin')
            elif change=='role':
                await users.update(member['id'],1,role='viewer',enabled=True,actor='admin')
            elif change=='password':
                await users.reset_password(member['id'],1,'StreamReplacementPassword-2026','admin')
            else:
                await db.pool.execute('ALTER TABLE user_accounts RENAME TO unavailable_accounts')
                renamed=True
            if not idle:stream.publish({'type':'alert','title':'must not reach revoked session'})
            with pytest.raises(ConnectionClosed) as closed:
                await asyncio.wait_for(ws.recv(),7 if idle else 2)
            assert closed.value.rcvd.code==expected_code
        async with asyncio.timeout(1):
            while stream._ws_subscribers:await asyncio.sleep(.01)
    finally:
        if renamed:await db.pool.execute('ALTER TABLE unavailable_accounts RENAME TO user_accounts')
        server.should_exit=True
        await asyncio.wait_for(task,3)
        listener.close()
