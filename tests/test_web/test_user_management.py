"""실제 관리 계정 API의 권한·감사·충돌·토큰 폐기를 검증한다."""

import json
from uuid import uuid4

import pytest

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_managed_auth import managed_case, login, PASSWORD


async def admin_headers(client):
    return {'Authorization': 'Bearer ' + await login(client)}


@pytest.mark.asyncio
async def test_account_lifecycle_audits_changes_without_credentials(managed_case, db):
    client, manager, users = managed_case
    headers = await admin_headers(client)
    response = await client.post('/api/users', headers=headers, json={
        'username': 'Support.Member', 'password': PASSWORD, 'role': 'analyst'})
    assert response.status_code == 201, response.text
    member = response.json()['user']
    assert member['username'] == 'support.member' and member['version'] == 1
    assert 'password' not in response.text
    token = await login(client, 'support.member')
    response = await client.put('/api/users/' + member['id'], headers=headers, json={
        'expected_version': 1, 'role': 'viewer', 'enabled': True})
    assert response.status_code == 200
    assert await manager.verify_token_async(token) is None
    token = await login(client, 'support.member')
    assert (await manager.verify_token_async(token))['role'] == 'viewer'
    replacement = 'ManagementReplacementPassword-2026'
    response = await client.post('/api/users/' + member['id'] + '/password', headers=headers,
        json={'expected_version': 2, 'password': replacement})
    assert response.status_code == 200 and response.json()['user']['version'] == 3
    assert await manager.verify_token_async(token) is None
    assert (await client.post('/api/auth/login', json={
        'username': 'support.member', 'password': PASSWORD})).status_code == 401
    token = await login(client, 'support.member', replacement)
    response = await client.put('/api/users/' + member['id'], headers=headers, json={
        'expected_version': 3, 'role': 'viewer', 'enabled': False})
    assert response.status_code == 200 and response.json()['user']['version'] == 4
    assert await manager.verify_token_async(token) is None
    listing = await client.get('/api/users?limit=1&offset=1', headers=headers)
    assert listing.status_code == 200 and listing.json()['total'] == 2
    assert listing.json()['users'][0]['enabled'] is False
    row = await client.get('/api/users/' + member['id'], headers=headers)
    assert row.json()['user']['changed_by'] == 'admin'
    details = [r['details'] for r in await db.pool.fetch(
        "SELECT details FROM audit_log WHERE resource LIKE '/api/users%' ORDER BY id")]
    text = json.dumps(details)
    assert PASSWORD not in text and replacement not in text and '$2b$' not in text
    outcomes = [d for d in details if d.get('outcome') == 'completed']
    assert len(outcomes) == 4
    assert outcomes[0]['before'] is None and outcomes[0]['after']['version'] == 1
    assert outcomes[1]['before']['role'] == 'analyst' and outcomes[1]['after']['role'] == 'viewer'
    assert outcomes[2]['before']['version'] == 2 and outcomes[2]['after']['version'] == 3
    assert outcomes[3]['after']['enabled'] is False
    for outcome in outcomes:
        history = await client.get('/api/audit/changes/' + outcome['request_id'], headers=headers)
        assert history.status_code == 200
        assert not history.json()['requires_reconciliation']


@pytest.mark.asyncio
@pytest.mark.parametrize('role', ['viewer', 'analyst'])
async def test_non_admin_cannot_list_or_change_accounts(managed_case, db, role):
    client, manager, users = managed_case
    member = await users.create('limited-member', PASSWORD, role, 'admin')
    headers = {'Authorization': 'Bearer ' + await login(client, 'limited-member')}
    requests = [('GET', '/api/users', None), ('GET', '/api/users/' + member['id'], None),
        ('POST', '/api/users', {'username': 'forbidden', 'password': PASSWORD, 'role': 'admin'}),
        ('PUT', '/api/users/' + member['id'], {'expected_version': 1, 'role': 'admin', 'enabled': True}),
        ('POST', '/api/users/' + member['id'] + '/password', {'expected_version': 1, 'password': PASSWORD})]
    for method, path, body in requests:
        assert (await client.request(method, path, headers=headers, json=body)).status_code == 403
    assert (await users.get(member['id']))['version'] == 1
    assert await db.pool.fetchval('SELECT count(*) FROM user_accounts') == 2
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='authorized_intent'") == 0


@pytest.mark.asyncio
async def test_duplicate_version_conflict_last_admin_and_missing_account(managed_case):
    client, manager, users = managed_case
    headers = await admin_headers(client)
    admin = (await users.list())['users'][0]
    duplicate = await client.post('/api/users', headers=headers,
        json={'username': 'ADMIN', 'password': PASSWORD, 'role': 'viewer'})
    assert duplicate.status_code == 409 and duplicate.json()['detail'] == 'username_exists'
    for change in ({'role': 'viewer', 'enabled': True}, {'role': 'admin', 'enabled': False}):
        result = await client.put('/api/users/' + admin['id'], headers=headers,
            json={'expected_version': 1, **change})
        assert result.status_code == 409 and result.json()['detail'] == 'last_administrator'
    assert (await users.get(admin['id']))['version'] == 1
    member = await users.create('conflict-member', PASSWORD, 'viewer', 'admin')
    assert (await client.put('/api/users/' + member['id'], headers=headers,
        json={'expected_version': 1, 'role': 'analyst', 'enabled': True})).status_code == 200
    for path, body in [('/api/users/' + member['id'],
            {'expected_version': 1, 'role': 'admin', 'enabled': True}),
            ('/api/users/' + member['id'] + '/password', {'expected_version': 1, 'password': PASSWORD})]:
        result = await client.request('POST' if path.endswith('/password') else 'PUT', path, headers=headers, json=body)
        assert result.status_code == 409
    assert (await users.get(member['id']))['version'] == 2
    assert (await client.get('/api/users/' + str(uuid4()), headers=headers)).status_code == 404
    assert (await client.put('/api/users/' + str(uuid4()), headers=headers,
        json={'expected_version': 1, 'role': 'viewer', 'enabled': True})).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['authorized_intent', 'change_prepared', 'api_mutation'])
async def test_required_audit_failure_blocks_or_reports_unknown_result(managed_case, db, monkeypatch, failure):
    client, manager, users = managed_case
    headers = await admin_headers(client)
    audit = client._transport.app.state.audit_logger
    original = audit.log

    async def log(**entry):
        return False if entry['action'] == failure else await original(**entry)

    monkeypatch.setattr(audit, 'log', log)
    result = await client.post('/api/users', headers=headers,
        json={'username': 'audit-member', 'password': PASSWORD, 'role': 'viewer'})
    assert result.status_code == 503
    member = await users.get_by_username('audit-member')
    if failure == 'api_mutation':
        assert member is not None
        assert result.json()['code'] == 'audit_outcome_unavailable'
        assert result.json()['execution_status'] == 'unknown'
        assert result.json()['request_id']
    else:
        assert member is None
    assert await db.pool.fetchval('SELECT count(*) FROM user_accounts') == (2 if member else 1)


@pytest.mark.asyncio
async def test_invalid_input_never_persists_or_echoes_password(managed_case, db):
    client, manager, users = managed_case
    headers = await admin_headers(client)
    for password in ('tiny-secret', 'X' * 73, '한' * 25):
        result = await client.post('/api/users', headers=headers,
            json={'username': 'invalid-member', 'password': password, 'role': 'viewer'})
        assert result.status_code == 422 and password not in result.text
    assert await db.pool.fetchval('SELECT count(*) FROM user_accounts') == 1
    admin = (await users.list())['users'][0]
    for body in ({'expected_version': True, 'role': 'viewer', 'enabled': True},
                 {'expected_version': 1, 'role': 'viewer', 'enabled': 'false'},
                 {'expected_version': 1, 'role': 'owner', 'enabled': True}):
        result = await client.put('/api/users/' + admin['id'], headers=headers, json=body)
        assert result.status_code == 422
    assert (await users.get(admin['id']))['version'] == 1


@pytest.mark.asyncio
async def test_audit_after_state_matches_this_commit_not_following_change(managed_case, db, monkeypatch):
    client, manager, users = managed_case
    headers = await admin_headers(client)
    original = users.create

    async def create(*args):
        row = await original(*args)
        await users.update(row['id'], 1, role='analyst', enabled=True, actor='following administrator')
        return row

    monkeypatch.setattr(users, 'create', create)
    response = await client.post('/api/users', headers=headers,
        json={'username': 'followed-member', 'password': PASSWORD, 'role': 'viewer'})
    assert response.status_code == 201 and response.json()['user']['version'] == 1
    current = await users.get_by_username('followed-member')
    assert current['version'] == 2 and current['role'] == 'analyst'
    details = await db.pool.fetchval("SELECT details FROM audit_log WHERE action='api_mutation' AND resource='/api/users' ORDER BY id DESC LIMIT 1")
    assert details['after']['version'] == 1 and details['after']['role'] == 'viewer'
