"""OIDC 연결은 명시적 식별자만 사용하고 변경 시 기존 로그인을 폐기한다."""

import asyncio
import uuid

import pytest

from netwatcher.storage.oidc_identities import OidcIdentities, issuer, subject
from netwatcher.storage.user_accounts import AccountConflict, UserAccounts
from tests.test_web.test_managed_auth import managed_case, login
from tests.test_web.test_business_reviews import review_case

PASSWORD = 'IdentityFixturePassword-2026'
ISSUER = 'https://identity.example/tenant'


@pytest.mark.parametrize('value', ['http://identity.example', 'https://',
    'https://user:password@identity.example', 'https://identity.example?query=1',
    'https://identity.example#fragment', 'https://identity.example:invalid',
    'https://identity.example\n', None, 'x' * 513])
def test_invalid_issuer(value):
    with pytest.raises(ValueError):
        issuer(value)


@pytest.mark.parametrize('value', ['', ' ', 'user\x00', 'user\n', '사용자', 'x' * 256, None])
def test_invalid_subject(value):
    with pytest.raises(ValueError):
        subject(value)


@pytest.mark.asyncio
async def test_exact_identity_and_local_role_only(db):
    users = UserAccounts(db)
    admin = await users.create('admin', PASSWORD, 'admin', 'setup')
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    identities = OidcIdentities(db)
    assert await identities.resolve(ISSUER, 'member') is None
    linked = await identities.link(member['id'], 1, ISSUER, 'External-123', 'admin')
    assert linked['user']['version'] == 2
    assert linked['identity']['user_id'] == member['id']
    resolved = await identities.resolve(ISSUER, 'External-123')
    assert resolved['id'] == member['id'] and resolved['role'] == 'viewer'
    assert 'password_hash' not in resolved
    for other_issuer, other_sub in [(ISSUER + '/', 'External-123'),
            (ISSUER.upper(), 'External-123'), (ISSUER, 'external-123'),
            (ISSUER, 'member'), (ISSUER, ' External-123')]:
        assert await identities.resolve(other_issuer, other_sub) is None
    disabled = await users.update(member['id'], 2, role='viewer', enabled=False, actor='admin')
    assert disabled['version'] == 3
    assert await identities.resolve(ISSUER, 'External-123') is None
    assert len(await identities.for_user(member['id'])) == 1
    assert await identities.for_user(admin['id']) == []


@pytest.mark.asyncio
async def test_link_and_unlink_revoke_existing_sessions(managed_case):
    client, manager, users = managed_case
    member = await users.create('member', PASSWORD, 'analyst', 'admin')
    identities = OidcIdentities(users.db)
    token = await login(client, 'member', PASSWORD)
    linked = await identities.link(member['id'], 1, ISSUER, 'external-member', 'admin')
    assert await manager.verify_token_async(token) is None
    next_token = await login(client, 'member', PASSWORD)
    assert (await manager.verify_token_async(next_token))['ver'] == 2
    removed = await identities.unlink(member['id'], 2, linked['identity']['id'], 'admin')
    assert removed['user']['version'] == 3
    assert await manager.verify_token_async(next_token) is None
    assert await identities.resolve(ISSUER, 'external-member') is None


@pytest.mark.asyncio
async def test_conflicts_never_change_account_or_binding(db):
    users = UserAccounts(db)
    one = await users.create('one', PASSWORD, 'admin', 'setup')
    two = await users.create('two', PASSWORD, 'viewer', 'one')
    identities = OidcIdentities(db)
    linked = await identities.link(one['id'], 1, ISSUER, 'subject-one', 'one')
    for user_id, ver, sub, reason in [(one['id'], 1, 'different', 'version_changed'),
            (two['id'], 1, 'subject-one', 'subject_already_linked'),
            (one['id'], 2, 'different', 'issuer_already_linked')]:
        with pytest.raises(AccountConflict, match=reason):
            await identities.link(user_id, ver, ISSUER, sub, 'one')
    with pytest.raises(AccountConflict, match='identity_missing'):
        await identities.unlink(two['id'], 1, linked['identity']['id'], 'one')
    with pytest.raises(AccountConflict, match='account_missing'):
        await identities.link(uuid.uuid4(), 1, ISSUER, 'missing', 'one')
    assert (await users.get(one['id']))['version'] == 2
    assert (await users.get(two['id']))['version'] == 1
    assert (await identities.resolve(ISSUER, 'subject-one'))['id'] == one['id']


@pytest.mark.asyncio
async def test_concurrent_link_cannot_assign_one_subject_to_two_users(db):
    users = UserAccounts(db)
    one = await users.create('one', PASSWORD, 'admin', 'setup')
    two = await users.create('two', PASSWORD, 'analyst', 'one')
    identities = OidcIdentities(db)
    results = await asyncio.gather(*(identities.link(user['id'], 1, ISSUER, 'shared', 'one')
        for user in (one, two)), return_exceptions=True)
    assert sum(isinstance(result, AccountConflict) for result in results) == 1
    assert sum(isinstance(result, dict) for result in results) == 1
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_identities') == 1
    versions = [(await users.get(user['id']))['version'] for user in (one, two)]
    assert sorted(versions) == [1, 2]


@pytest.mark.asyncio
async def test_capacity_rejects_link_without_revoking_account(db, monkeypatch):
    import netwatcher.storage.oidc_identities as module
    users = UserAccounts(db)
    one = await users.create('one', PASSWORD, 'admin', 'setup')
    identities = OidcIdentities(db)
    monkeypatch.setattr(module, 'MAX_IDENTITIES', 1)
    await identities.link(one['id'], 1, ISSUER, 'first', 'one')
    with pytest.raises(AccountConflict, match='identity_capacity'):
        await identities.link(one['id'], 2, 'https://other.example', 'second', 'one')
    assert (await users.get(one['id']))['version'] == 2
    assert len(await identities.for_user(one['id'])) == 1


@pytest.mark.asyncio
async def test_failed_epoch_update_rolls_back_binding_change(db, monkeypatch):
    users = UserAccounts(db)
    one = await users.create('one', PASSWORD, 'admin', 'setup')
    identities = OidcIdentities(db)
    original = identities._bump

    async def failed_bump(*args):
        raise RuntimeError('Injected account update failure')

    monkeypatch.setattr(identities, '_bump', failed_bump)
    with pytest.raises(RuntimeError):
        await identities.link(one['id'], 1, ISSUER, 'first', 'one')
    assert await identities.for_user(one['id']) == []
    assert (await users.get(one['id']))['version'] == 1
    monkeypatch.setattr(identities, '_bump', original)
    linked = await identities.link(one['id'], 1, ISSUER, 'first', 'one')
    monkeypatch.setattr(identities, '_bump', failed_bump)
    with pytest.raises(RuntimeError):
        await identities.unlink(one['id'], 2, linked['identity']['id'], 'one')
    assert (await identities.resolve(ISSUER, 'first'))['id'] == one['id']
    assert (await users.get(one['id']))['version'] == 2
