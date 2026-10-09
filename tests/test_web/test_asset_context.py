"""실제 PostgreSQL의 수동 역할 확인·매핑 수명·동시 변경 계약."""
import asyncio
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.inventory.context import asset_context
from netwatcher.web.routes.devices import create_devices_router
from netwatcher.web.auth import AuthManager

MAC = '02:00:00:00:00:10'
IP = '192.0.2.10'


def request(version=0, **changes):
    return dict(role='nas', ip_address=IP, expected_version=version, valid_hours=168,
                ownership_confirmed=True, evidence='설치 위치와 담당자 확인', **changes)


def app_for(repo):
    app = FastAPI()
    app.include_router(create_devices_router(repo), prefix='/api')
    return app


@pytest.mark.asyncio
async def test_confirmation_is_versioned_and_atomic(db, device_repo):
    await device_repo.upsert(MAC, IP)
    async with AsyncClient(transport=ASGITransport(app=app_for(device_repo)), base_url='http://test') as client:
        response = await client.put(f'/api/devices/{MAC}/context', json=request())
        assert response.status_code == 200
        data = response.json()
        assert data['asset_context']['status'] == 'confirmed'
        assert data['asset_context']['role'] == 'nas'
        assert data['asset_context']['scope'] == 'current_inventory'
        assert data['device']['device_type'] == 'unknown'
        assert (await client.put(f'/api/devices/{MAC}/context', json=request())).status_code == 409
    assert await db.pool.fetchval('SELECT count(*) FROM asset_context_history') == 1
    # 이력 저장 실패는 활성 확인 UPDATE도 되돌려야 한다.
    await db.pool.execute("CREATE FUNCTION reject_history() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'failed'; END $$ LANGUAGE plpgsql")
    await db.pool.execute('CREATE TRIGGER reject_history BEFORE INSERT ON asset_context_history FOR EACH ROW EXECUTE FUNCTION reject_history()')
    with pytest.raises(Exception, match='failed'):
        await device_repo.confirm_context(MAC, IP, 1, {'role': 'backup'})
    assert (await device_repo.get_by_mac(MAC))['context_version'] == 1


@pytest.mark.asyncio
async def test_mapping_changes_do_not_resurrect_confirmation(device_repo):
    await device_repo.upsert(MAC, IP)
    async with AsyncClient(transport=ASGITransport(app=app_for(device_repo)), base_url='http://test') as client:
        assert (await client.put(f'/api/devices/{MAC}/context', json=request())).status_code == 200
        await device_repo.upsert(MAC, '192.0.2.11')
        await device_repo.upsert(MAC, IP)
        context = (await client.get(f'/api/devices/{MAC}')).json()['device']['asset_context']
        assert context['status'] == 'unknown' and context['reason'] == 'mapping_changed'
        assert (await client.put(f'/api/devices/{MAC}/context', json=request(1))).status_code == 200
        # 일반 속성 갱신은 매핑 세대를 바꾸지 않는다.
        await device_repo.update_device(MAC, nickname='nas')
        assert (await device_repo.context_for_source(IP, MAC))['status'] == 'confirmed'
        assert (await device_repo.context_for_source(IP, '02:00:00:00:00:99'))['status'] == 'unknown'


@pytest.mark.asyncio
async def test_shared_ip_invalidates_role_and_allows_revocation(device_repo):
    await device_repo.upsert(MAC, IP)
    async with AsyncClient(transport=ASGITransport(app=app_for(device_repo)), base_url='http://test') as client:
        assert (await client.put(f'/api/devices/{MAC}/context', json=request())).status_code == 200
        await device_repo.upsert('02:00:00:00:00:20', IP)
        assert (await device_repo.context_for_source(IP, MAC))['reason'] == 'shared_ip'
        assert (await client.put(f'/api/devices/{MAC}/context', json=request(1))).status_code == 409
        payload=request(1);payload['role']='unknown'
        response=await client.put(f'/api/devices/{MAC}/context',json=payload)
        assert response.status_code == 200
        assert response.json()['asset_context']['reason'] == 'revoked'


@pytest.mark.asyncio
async def test_concurrent_confirmation_only_one_wins(db, device_repo):
    await device_repo.upsert(MAC, IP)
    async with AsyncClient(transport=ASGITransport(app=app_for(device_repo)), base_url='http://test') as client:
        responses = await asyncio.gather(*[client.put(f'/api/devices/{MAC}/context', json=request()) for _ in range(2)])
    assert sorted(r.status_code for r in responses) == [200, 409]
    assert await db.pool.fetchval('SELECT count(*) FROM asset_context_history') == 1


@pytest.mark.parametrize('change', [{'valid_hours':721}, {'ownership_confirmed':False}, {'ip_address':'not-an-ip'}, {'role':'auto-nas'}, {'evidence':'   '}])
@pytest.mark.asyncio
async def test_invalid_confirmation_rejected(device_repo, change):
    await device_repo.upsert(MAC, IP)
    payload=request();payload.update(change)
    async with AsyncClient(transport=ASGITransport(app=app_for(device_repo)), base_url='http://test') as client:
        assert (await client.put(f'/api/devices/{MAC}/context', json=payload)).status_code == 422


@pytest.mark.parametrize('role, status', [('viewer',403),('analyst',403),('admin',200)])
@pytest.mark.asyncio
async def test_verified_role_required(config, device_repo, monkeypatch, role, status):
    await device_repo.upsert(MAC,IP)
    monkeypatch.setenv('NETWATCHER_LOGIN_ENABLED','true')
    # Explicit test AuthManager configuration without production credentials.
    config._data['auth']={'enabled':True,'password':'test-asset-context-password'}
    auth=AuthManager(config)
    app=app_for(device_repo);app.state.auth_manager=auth
    token=jwt.encode({'sub':'reviewer','role':role,'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},auth._secret,algorithm='HS256')
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        response=await client.put(f'/api/devices/{MAC}/context',json=request(),headers={'Authorization':'Bearer '+token})
        assert response.status_code==status


def test_expiry_is_explicit():
    now=datetime.now(timezone.utc)
    context=asset_context({'ip_address':IP,'ip_mapping_version':0,'context_profile':{'role':'nas','ip':IP,'mapping_version':0,'expires_at':(now-timedelta(seconds=1)).isoformat()}},now=now)
    assert context['status']=='unknown' and context['reason']=='expired'


@pytest.mark.asyncio
async def test_ip_only_event_does_not_inherit_confirmed_ownership(device_repo):
    await device_repo.upsert(MAC, IP)
    async with AsyncClient(transport=ASGITransport(app=app_for(device_repo)), base_url='http://test') as client:
        assert (await client.put(f'/api/devices/{MAC}/context', json=request())).status_code == 200
    assert (await device_repo.context_for_source(IP, MAC))['status'] == 'confirmed'
    context = await device_repo.context_for_source(IP, None)
    assert context['status'] == 'unknown'
    assert context['reason'] == 'source_mac_missing'
    assert 'role' not in context
