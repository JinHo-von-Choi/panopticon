"""브라우저 요청부터 실제 HTTPS 교환과 로컬 권한의 토큰 발급까지 확인한다."""

import secrets
from urllib.parse import urlsplit, parse_qs

import pytest

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_managed_auth import managed_case, PASSWORD
from tests.test_web.test_oidc_provider import provider
from netwatcher.storage.oidc_identities import OidcIdentities
from netwatcher.web.oidc import OidcTokenInvalid, OidcProviderUnavailable
from netwatcher.web.oidc_login import OidcLogin


async def begin(service, state):
    pending = await service.begin()
    query = parse_qs(urlsplit(pending['url']).query)
    state['nonce'], state['challenge'] = query['nonce'][0], query['code_challenge'][0]
    return pending, query['state'][0]


@pytest.mark.asyncio
async def test_real_code_exchange_uses_local_role_and_rejects_reuse(managed_case, provider):
    client, auth, users = managed_case
    external, state, _ = provider
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    await OidcIdentities(users.db).link(member['id'], 1, external.issuer, 'external-subject', 'admin')
    service = OidcLogin(auth, external)
    pending, request_state = await begin(service, state)
    token = await service.finish(state=request_state, browser=pending['browser'], code='valid-code')
    verified = await auth.verify_token_async(token)
    assert verified['uid'] == member['id'] and verified['role'] == 'viewer' and verified['ver'] == 2
    with pytest.raises(OidcTokenInvalid):
        await service.finish(state=request_state, browser=pending['browser'], code='valid-code')
    assert state['requests'].count(('POST', '/token')) == 1
    await users.update(member['id'], 2, role='viewer', enabled=False, actor='admin')
    assert await auth.verify_token_async(token) is None


@pytest.mark.asyncio
async def test_wrong_browser_does_not_exchange_code(managed_case, provider):
    client, auth, users = managed_case
    external, state, _ = provider
    service = OidcLogin(auth, external)
    pending, request_state = await begin(service, state)
    with pytest.raises(OidcTokenInvalid):
        await service.finish(state=request_state, browser=secrets.token_urlsafe(32), code='valid-code')
    assert ('POST', '/token') not in state['requests']
    assert await users.db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('disabled', [False, True])
async def test_unknown_or_disabled_identity_cannot_login(managed_case, provider, disabled):
    client, auth, users = managed_case
    external, state, _ = provider
    if disabled:
        member = await users.create('member', PASSWORD, 'viewer', 'admin')
        await OidcIdentities(users.db).link(member['id'], 1, external.issuer, 'external-subject', 'admin')
        await users.update(member['id'], 2, role='viewer', enabled=False, actor='admin')
    service = OidcLogin(auth, external)
    pending, request_state = await begin(service, state)
    with pytest.raises(OidcTokenInvalid):
        await service.finish(state=request_state, browser=pending['browser'], code='valid-code')
    assert await users.db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0
    assert (await users.list())['total'] == (2 if disabled else 1)


@pytest.mark.asyncio
async def test_provider_failure_cleans_start_and_consumes_callback_state(managed_case, provider):
    client, auth, users = managed_case
    external, state, _ = provider
    service = OidcLogin(auth, external)
    state['fault'] = 'invalid_json'
    with pytest.raises(OidcProviderUnavailable):
        await service.begin()
    assert await users.db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0
    state['fault'] = None
    pending, request_state = await begin(service, state)
    state['fault'] = 'wrong_nonce'
    with pytest.raises(OidcTokenInvalid):
        await service.finish(state=request_state, browser=pending['browser'], code='valid-code')
    assert await users.db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0


@pytest.mark.asyncio
async def test_role_change_after_identity_lookup_prevents_token_delivery(managed_case, provider, monkeypatch):
    client, auth, users = managed_case
    external, state, _ = provider
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    await OidcIdentities(users.db).link(member['id'], 1, external.issuer, 'external-subject', 'admin')
    service = OidcLogin(auth, external)
    original = service.identities.resolve

    async def changed_after_lookup(*args):
        row = await original(*args)
        await users.update(member['id'], 2, role='analyst', enabled=True, actor='admin')
        return row

    monkeypatch.setattr(service.identities, 'resolve', changed_after_lookup)
    pending, request_state = await begin(service, state)
    with pytest.raises(OidcTokenInvalid, match='Account changed during login'):
        await service.finish(state=request_state, browser=pending['browser'], code='valid-code')
    assert (await users.get(member['id']))['version'] == 3
    assert await users.db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0


@pytest.mark.asyncio
async def test_simultaneous_callbacks_exchange_only_once(managed_case, provider):
    import asyncio
    client, auth, users = managed_case
    external, state, _ = provider
    admin = (await users.list())['users'][0]
    await OidcIdentities(users.db).link(admin['id'], 1, external.issuer, 'external-subject', 'admin')
    service = OidcLogin(auth, external)
    pending, request_state = await begin(service, state)
    results = await asyncio.gather(*(service.finish(state=request_state, browser=pending['browser'],
        code='valid-code') for _ in range(2)), return_exceptions=True)
    assert sum(isinstance(result, str) for result in results) == 1
    assert sum(isinstance(result, OidcTokenInvalid) for result in results) == 1
    assert state['requests'].count(('POST', '/token')) == 1


@pytest.mark.asyncio
async def test_state_storage_unavailable_never_exchanges_code(managed_case, provider, monkeypatch):
    import asyncpg
    from netwatcher.web.auth import AuthStateUnavailable
    client, auth, users = managed_case
    external, state, _ = provider
    service = OidcLogin(auth, external)
    original = service.requests.create

    async def unavailable(*args, **kwargs):
        raise asyncpg.InterfaceError('Injected storage outage')

    monkeypatch.setattr(service.requests, 'create', unavailable)
    with pytest.raises(AuthStateUnavailable):
        await service.begin()
    assert state['requests'] == []
    monkeypatch.setattr(service.requests, 'create', original)
    pending, request_state = await begin(service, state)
    monkeypatch.setattr(service.requests, 'consume', unavailable)
    with pytest.raises(AuthStateUnavailable):
        await service.finish(state=request_state, browser=pending['browser'], code='valid-code')
    assert ('POST', '/token') not in state['requests']
    assert await users.db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1
