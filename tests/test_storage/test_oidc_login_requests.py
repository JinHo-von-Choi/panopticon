"""실제 DB에서 암호화·브라우저 결합·동시 사용·기간과 한도를 확인한다."""

import asyncio
import base64
import hashlib
import secrets

import pytest

from netwatcher.storage.oidc_login_requests import OidcLoginRequests, OidcRequestCapacity


@pytest.mark.asyncio
async def test_encryption_browser_binding_and_one_time_consumption(db):
    requests = OidcLoginRequests(db, secrets.token_urlsafe(32), 'fixture-provider')
    pending = await requests.create()
    stored = dict(await db.pool.fetchrow('SELECT * FROM oidc_login_requests'))
    for field in ('state', 'browser', 'nonce'):
        assert pending[field] not in str(stored)
    assert await requests.consume(pending['state'], secrets.token_urlsafe(32)) is None
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1
    result = await requests.consume(pending['state'], pending['browser'])
    assert result['nonce'] == pending['nonce']
    challenge = base64.urlsafe_b64encode(hashlib.sha256(result['verifier'].encode()).digest()).rstrip(b'=').decode()
    assert challenge == pending['challenge']
    assert result['verifier'] not in str(stored)
    assert await requests.consume(pending['state'], pending['browser']) is None


@pytest.mark.asyncio
async def test_two_instances_cannot_consume_same_request(db):
    secret = secrets.token_urlsafe(32)
    one, two = (OidcLoginRequests(db, secret, 'fixture-provider') for _ in range(2))
    pending = await one.create()
    results = await asyncio.gather(*(repo.consume(pending['state'], pending['browser']) for repo in (one, two)))
    assert sum(result is not None for result in results) == 1
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0


@pytest.mark.asyncio
async def test_expiry_and_restart_context_or_secret_changes(db):
    secret = secrets.token_urlsafe(32)
    requests = OidcLoginRequests(db, secret, 'fixture-provider')
    pending = await requests.create()
    restarted = OidcLoginRequests(db, secret, 'fixture-provider')
    assert await restarted.consume(pending['state'], pending['browser']) is not None
    for other in (OidcLoginRequests(db, secret, 'different-provider'),
                  OidcLoginRequests(db, secrets.token_urlsafe(32), 'fixture-provider')):
        pending = await requests.create()
        assert await other.consume(pending['state'], pending['browser']) is None
        assert await requests.consume(pending['state'], pending['browser']) is None
    expired = await requests.create()
    await db.pool.execute("UPDATE oidc_login_requests SET expires_at=clock_timestamp()-interval '1 second'")
    assert await requests.consume(expired['state'], expired['browser']) is None
    await requests.create()
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1


@pytest.mark.asyncio
async def test_tamper_capacity_cleanup_and_invalid_input(db, monkeypatch):
    import netwatcher.storage.oidc_login_requests as module
    requests = OidcLoginRequests(db, secrets.token_urlsafe(32), 'fixture-provider')
    monkeypatch.setattr(module, 'MAX_PENDING', 1)
    pending = await requests.create()
    with pytest.raises(OidcRequestCapacity):
        await requests.create()
    for state, browser in [(None, pending['browser']), ('x' * 4096, pending['browser']),
                           (pending['state'], '한글')]:
        assert await requests.consume(state, browser) is None
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1
    await db.pool.execute("UPDATE oidc_login_requests SET protected='tampered'")
    assert await requests.consume(pending['state'], pending['browser']) is None
    pending = await requests.create()
    await requests.discard(pending['state'], secrets.token_urlsafe(32))
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1
    await requests.discard(pending['state'], pending['browser'])
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 0


@pytest.mark.asyncio
async def test_concurrent_capacity_cannot_overflow(db, monkeypatch):
    import netwatcher.storage.oidc_login_requests as module
    requests = OidcLoginRequests(db, secrets.token_urlsafe(32), 'fixture-provider')
    monkeypatch.setattr(module, 'MAX_PENDING', 1)
    results = await asyncio.gather(requests.create(), requests.create(), return_exceptions=True)
    assert sum(isinstance(result, dict) for result in results) == 1
    assert sum(isinstance(result, OidcRequestCapacity) for result in results) == 1
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_login_requests') == 1


@pytest.mark.asyncio
async def test_session_delivery_is_encrypted_bound_and_single_use(db):
    requests = OidcLoginRequests(db, secrets.token_urlsafe(32), 'fixture-provider')
    browser = secrets.token_urlsafe(32)
    token = 'signed-session-fixture'
    ticket = await requests.deliver(token, browser)
    stored = str(dict(await db.pool.fetchrow('SELECT * FROM oidc_login_requests')))
    assert token not in stored and ticket not in stored and browser not in stored
    assert await requests.redeem(ticket, secrets.token_urlsafe(32)) is None
    values = await asyncio.gather(requests.redeem(ticket, browser), requests.redeem(ticket, browser))
    assert values.count(token) == 1 and values.count(None) == 1


@pytest.mark.asyncio
async def test_login_and_session_delivery_cannot_be_interchanged(db):
    requests = OidcLoginRequests(db, secrets.token_urlsafe(32), 'fixture-provider')
    pending = await requests.create()
    assert await requests.redeem(pending['state'], pending['browser']) is None
    ticket = await requests.deliver('signed-session-fixture', pending['browser'])
    assert await requests.consume(ticket, pending['browser']) is None
