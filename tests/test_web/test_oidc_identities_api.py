"""OIDC 연결 API의 관리자 권한·감사 기록·세션 폐기를 확인한다."""

import json

import pytest

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_managed_auth import managed_case, login, PASSWORD

ISSUER = 'https://identity.example/tenant'


@pytest.mark.asyncio
async def test_identity_lifecycle_and_private_audit(managed_case, db):
    client, manager, users = managed_case
    member = await users.create('member', PASSWORD, 'analyst', 'admin')
    headers = {'Authorization': 'Bearer ' + await login(client)}
    member_token = await login(client, 'member')
    path = '/api/users/' + member['id'] + '/identities'
    response = await client.post(path, headers=headers, json={
        'expected_version': 1, 'issuer': ISSUER, 'subject': 'provider-private-123'})
    assert response.status_code == 201, response.text
    linked = response.json()
    assert linked['user']['version'] == 2
    assert await manager.verify_token_async(member_token) is None
    listing = await client.get(path, headers=headers)
    assert listing.json()['identities'] == [linked['identity']]
    assert (await client.post(path, headers=headers, json={
        'expected_version': 1, 'issuer': ISSUER, 'subject': 'other'})).status_code == 409
    member_token = await login(client, 'member')
    removed = await client.request('DELETE', path + '/' + linked['identity']['id'],
        headers=headers, json={'expected_version': 2})
    assert removed.status_code == 200 and removed.json()['user']['version'] == 3
    assert await manager.verify_token_async(member_token) is None
    assert (await client.get(path, headers=headers)).json()['identities'] == []
    rows = await db.pool.fetch("SELECT details FROM audit_log WHERE resource LIKE $1 ORDER BY id", path + '%')
    details = [row['details'] for row in rows]
    serialized = json.dumps(details)
    assert ISSUER not in serialized and 'provider-private-123' not in serialized
    outcomes = [item for item in details if item.get('outcome') == 'completed']
    assert len(outcomes) == 2
    assert outcomes[0]['before']['version'] == 1 and outcomes[0]['after']['version'] == 2
    assert outcomes[0]['after']['operation'] == 'link'
    assert outcomes[1]['before']['version'] == 2 and outcomes[1]['after']['version'] == 3
    assert outcomes[1]['after']['operation'] == 'unlink'


@pytest.mark.asyncio
@pytest.mark.parametrize('role', ['viewer', 'analyst'])
async def test_non_admin_cannot_read_or_change_identity(managed_case, db, role):
    client, manager, users = managed_case
    member = await users.create('limited', PASSWORD, role, 'admin')
    headers = {'Authorization': 'Bearer ' + await login(client, 'limited')}
    path = '/api/users/' + member['id'] + '/identities'
    for method, endpoint, body in [('GET', path, None), ('POST', path,
        {'expected_version': 1, 'issuer': ISSUER, 'subject': 'limited'}),
        ('DELETE', path + '/00000000-0000-0000-0000-000000000001', {'expected_version': 1})]:
        assert (await client.request(method, endpoint, headers=headers, json=body)).status_code == 403
    assert await db.pool.fetchval('SELECT count(*) FROM oidc_identities') == 0
    assert (await users.get(member['id']))['version'] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['authorized_intent', 'change_prepared', 'api_mutation'])
async def test_audit_failure_blocks_or_reports_unknown_link(managed_case, db, monkeypatch, failure):
    client, manager, users = managed_case
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    headers = {'Authorization': 'Bearer ' + await login(client)}
    logger = client._transport.app.state.audit_logger
    original = logger.log

    async def fail_prepared(*args, **kwargs):
        if kwargs.get('action') == failure:
            return False
        return await original(*args, **kwargs)

    monkeypatch.setattr(logger, 'log', fail_prepared)
    response = await client.post('/api/users/' + member['id'] + '/identities',
        headers=headers, json={'expected_version': 1, 'issuer': ISSUER, 'subject': 'member'})
    assert response.status_code == 503
    if failure == 'api_mutation':
        assert response.json()['code'] == 'audit_outcome_unavailable'
        assert response.json()['execution_status'] == 'unknown'
        assert await db.pool.fetchval('SELECT count(*) FROM oidc_identities') == 1
        assert (await users.get(member['id']))['version'] == 2
        current = await client.get('/api/users/' + member['id'] + '/identities', headers=headers)
        assert current.json()['user']['version'] == 2
        assert current.json()['identities'][0]['subject'] == 'member'
    else:
        assert await db.pool.fetchval('SELECT count(*) FROM oidc_identities') == 0
        assert (await users.get(member['id']))['version'] == 1


@pytest.mark.asyncio
async def test_audit_after_uses_this_binding_commit(managed_case, db, monkeypatch):
    from netwatcher.storage.oidc_identities import OidcIdentities
    client, manager, users = managed_case
    member = await users.create('member', PASSWORD, 'viewer', 'admin')
    headers = {'Authorization': 'Bearer ' + await login(client)}
    original = OidcIdentities.link

    async def followed_link(self, *args, **kwargs):
        result = await original(self, *args, **kwargs)
        await users.update(member['id'], 2, role='analyst', enabled=True, actor='following-admin')
        return result

    monkeypatch.setattr(OidcIdentities, 'link', followed_link)
    path = '/api/users/' + member['id'] + '/identities'
    response = await client.post(path, headers=headers, json={
        'expected_version': 1, 'issuer': ISSUER, 'subject': 'member'})
    assert response.status_code == 201 and response.json()['user']['version'] == 2
    assert (await users.get(member['id']))['version'] == 3
    details = await db.pool.fetchval("SELECT details FROM audit_log WHERE action='api_mutation' AND resource=$1 ORDER BY id DESC LIMIT 1", path)
    assert details['after']['version'] == 2 and details['after']['operation'] == 'link'
