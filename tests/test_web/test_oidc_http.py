"""실제 DB·HTTPS 공급자로 콘솔 로그인 경로와 보안 쿠키를 확인한다."""

import secrets
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_managed_auth import managed_case, PASSWORD
from tests.test_web.test_oidc_provider import provider
from netwatcher.storage.oidc_identities import OidcIdentities
from netwatcher.storage.repositories import EventRepository, DeviceRepository, TrafficStatsRepository
from netwatcher.alerts.stream import EventStream
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
from netwatcher.web.oidc import OidcProvider
from netwatcher.web.routes.oidc import BROWSER_COOKIE, DELIVERY_COOKIE


@pytest_asyncio.fixture
async def oidc_http(managed_case, provider, config, db, monkeypatch):
    _, auth, users = managed_case
    external, state, ssl_context = provider
    config.raw['auth']['oidc'] = {'enabled': True, 'issuer': external.issuer,
        'client_id': external.client_id, 'redirect_uri': external.redirect_uri}
    import netwatcher.web.oidc_login as module
    original = OidcProvider
    monkeypatch.setattr(module, 'OidcProvider', lambda *args, **kwargs:
        original(*args, **kwargs, ssl_context=ssl_context))
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db), EventStream(),
        auth_manager=auth, audit_logger=AuditLogger(db.pool), audit_required=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url='https://console.example') as client:
        yield client, app.state.oidc_login, state, users


async def start(client, state):
    response = await client.get('/api/auth/oidc/start')
    assert response.status_code == 303, response.text
    query = parse_qs(urlsplit(response.headers['location']).query)
    state['nonce'], state['challenge'] = query['nonce'][0], query['code_challenge'][0]
    return response, query['state'][0]


@pytest.mark.asyncio
async def test_http_login_cookie_delivery_and_local_permissions(oidc_http, db):
    client, service, state, users = oidc_http
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    await OidcIdentities(db).link(member['id'], 1, service.provider.issuer, 'external-subject', 'admin')
    status = (await client.get('/api/auth/status')).json()
    assert status['oidc']['enabled'] is True
    response, request_state = await start(client, state)
    cookies = response.headers.get_list('set-cookie')
    assert any(BROWSER_COOKIE in c and all(flag in c for flag in ('Secure', 'HttpOnly', 'SameSite=lax', 'Path=/')) for c in cookies)
    callback = await client.get('/api/auth/oidc/callback', params={'state': request_state, 'code': 'valid-code'})
    assert callback.status_code == 303 and callback.headers['location'] == 'https://console.example/?oidc=finish'
    assert callback.headers['cache-control'] == 'no-store' and callback.headers['referrer-policy'] == 'no-referrer'
    assert client.cookies.get(DELIVERY_COOKIE)
    stored = str([dict(row) for row in await db.pool.fetch('SELECT * FROM oidc_login_requests')])
    delivered = await client.post('/api/auth/oidc/session', headers={'Origin': 'https://console.example'})
    assert delivered.status_code == 200, delivered.text
    token = delivered.json()['token']
    assert token not in stored and token not in callback.headers['location']
    assert client.cookies.get(BROWSER_COOKIE) is None and client.cookies.get(DELIVERY_COOKIE) is None
    identity = await service.auth.verify_token_async(token)
    assert identity['role'] == 'viewer' and identity['uid'] == member['id'] and identity['ver'] == 2
    assert (await client.get('/api/events', headers={'Authorization': 'Bearer ' + token})).status_code == 200
    assert (await client.get('/api/users', headers={'Authorization': 'Bearer ' + token})).status_code == 403
    assert (await client.post('/api/auth/oidc/session', headers={'Origin': 'https://console.example'})).status_code == 401
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('origin', [None, 'https://attacker.example'])
async def test_cross_origin_session_request_preserves_pending_delivery(oidc_http, origin):
    client, service, state, users = oidc_http
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    await service.identities.link(member['id'], 1, service.provider.issuer, 'external-subject', 'admin')
    _, request_state = await start(client, state)
    await client.get('/api/auth/oidc/callback', params={'state': request_state, 'code': 'valid-code'})
    headers = {} if origin is None else {'Origin': origin}
    assert (await client.post('/api/auth/oidc/session', headers=headers)).status_code == 403
    assert (await client.post('/api/auth/oidc/session', headers={'Origin': 'https://console.example'})).status_code == 200


@pytest.mark.asyncio
async def test_copied_delivery_cookie_is_one_time_and_rechecks_account(oidc_http):
    client, service, state, users = oidc_http
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    await service.identities.link(member['id'], 1, service.provider.issuer, 'external-subject', 'admin')
    _, request_state = await start(client, state)
    await client.get('/api/auth/oidc/callback', params={'state': request_state, 'code': 'valid-code'})
    copied = dict(client.cookies)
    await users.update(member['id'], 2, role='viewer', enabled=False, actor='admin')
    assert (await client.post('/api/auth/oidc/session', headers={'Origin': 'https://console.example'})).status_code == 401
    client.cookies.update(copied)
    assert (await client.post('/api/auth/oidc/session', headers={'Origin': 'https://console.example'})).status_code == 401


@pytest.mark.asyncio
async def test_duplicate_callback_unknown_identity_and_insecure_origin(oidc_http):
    client, service, state, users = oidc_http
    _, request_state = await start(client, state)
    duplicate = await client.get('/api/auth/oidc/callback', params=[('state', request_state), ('state', 'other'), ('code', 'valid-code')])
    assert duplicate.headers['location'].endswith('/?oidc=failed')
    assert ('POST', '/token') not in state['requests']
    _, request_state = await start(client, state)
    unknown = await client.get('/api/auth/oidc/callback', params={'state': request_state, 'code': 'valid-code'})
    assert unknown.headers['location'].endswith('/?oidc=failed')
    assert (await users.list())['total'] == 1
    for url in ('http://console.example/api/auth/oidc/start', 'https://attacker.example/api/auth/oidc/start'):
        assert (await client.get(url)).status_code == 400
    assert (await client.get('/api/auth/oidc/start', headers={'Sec-Fetch-Site': 'cross-site'})).status_code == 403


@pytest.mark.asyncio
async def test_session_delivery_expiry(oidc_http, db):
    client, service, state, users = oidc_http
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    await service.identities.link(member['id'], 1, service.provider.issuer, 'external-subject', 'admin')
    _, request_state = await start(client, state)
    await client.get('/api/auth/oidc/callback', params={'state': request_state, 'code': 'valid-code'})
    await db.pool.execute("UPDATE oidc_login_requests SET expires_at=clock_timestamp()-interval '1 second'")
    assert (await client.post('/api/auth/oidc/session', headers={'Origin': 'https://console.example'})).status_code == 401
