"""담당 계정·인계 작성자 연결과 이름만 있는 기존 기록의 구분."""
from uuid import UUID, uuid4

import asyncpg
import pytest

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_managed_auth import managed_case, login, PASSWORD
from netwatcher.investigation.workflows import CaseWorkflows
from netwatcher.investigation.reviews import ReviewConflict
from netwatcher.storage.repositories import EventRepository
from netwatcher.web.routes.case_workflows import CaseRequest


async def case_setup(managed_case):
    client, manager, users = managed_case
    token = await login(client)
    actor = await manager.verify_token_async(token)
    event_id = (await client.get('/api/events', headers={'Authorization': 'Bearer ' + token})).json()['events'][0]['id']
    return client, users, actor, {'Authorization': 'Bearer ' + token}, event_id


def handover(**values):
    return {'expected_version': 0, 'status': 'investigating', 'note': '확인할 통신 상대를 담당자에게 인계합니다'} | values


@pytest.mark.asyncio
async def test_assignment_links_owner_and_author_and_preserves_history(managed_case, db):
    client, users, actor, headers, event_id = await case_setup(managed_case)
    member = await users.create('case-member', PASSWORD, 'analyst', 'admin')
    path = f'/api/events/{event_id}/case'
    result = await client.put(path, headers=headers, json=handover(owner_id=member['id']))
    assert result.status_code == 200, result.text
    current = result.json()['case']
    assert current['owner'] == 'case-member' and current['owner_id'] == member['id']
    assert current['actor_id'] == actor['uid'] and current['owner_enabled'] is True
    assert result.json()['history'][0]['owner_id'] == member['id']
    unchanged = await client.put(path, headers=headers,
        json=handover(owner='case-member', expected_version=1))
    assert unchanged.status_code == 200 and unchanged.json()['case']['owner_id'] == member['id']
    status = await client.get('/api/auth/status', headers=headers)
    assert status.json()['user_id'] == actor['uid']
    listing = await client.get('/api/events', headers=headers, params={'case_owner_id': member['id']})
    assert listing.json()['total'] == 1 and listing.json()['events'][0]['case_owner_id'] == member['id']
    assert (await client.get('/api/events', headers=headers, params={'case_owner_id': actor['uid']})).json()['total'] == 0
    export = await client.get('/api/events/export', headers=headers, params={'case_owner_id': member['id']})
    assert export.json()['total'] == 1
    report = await client.get('/api/reports/weekly', headers=headers)
    assert report.status_code == 200
    assert report.json()['events'][0]['owner_id'] == member['id']
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await db.pool.execute('DELETE FROM user_accounts WHERE id=$1', UUID(member['id']))
    assert await db.pool.fetchval('SELECT count(*) FROM case_history') == 2


@pytest.mark.asyncio
async def test_missing_disabled_or_mismatched_owner_cannot_be_assigned(managed_case, db):
    client, users, actor, headers, event_id = await case_setup(managed_case)
    member = await users.create('disabled-owner', PASSWORD, 'viewer', 'admin')
    await users.update(member['id'], 1, role='viewer', enabled=False, actor='admin')
    for body, reason in [(handover(owner_id=member['id']), 'owner_account_disabled'),
                         (handover(owner_id=str(uuid4())), 'owner_account_missing'),
                         (handover(owner_id=actor['uid'], owner='another person'), 'owner_account_mismatch')]:
        result = await client.put(f'/api/events/{event_id}/case', headers=headers, json=body)
        assert result.status_code == 409 and result.json()['detail'] == reason
    assert (await client.put(f'/api/events/{event_id}/case', headers=headers,
        json=handover(owner_id='invalid'))).status_code == 422
    assert await db.pool.fetchval('SELECT count(*) FROM case_workflows') == 0


@pytest.mark.asyncio
async def test_disabled_owner_is_visible_and_history_survives_reassignment(managed_case):
    client, users, actor, headers, event_id = await case_setup(managed_case)
    member = await users.create('retained-owner', PASSWORD, 'viewer', 'admin')
    path = f'/api/events/{event_id}/case'
    assert (await client.put(path, headers=headers, json=handover(owner_id=member['id']))).status_code == 200
    await users.update(member['id'], 1, role='viewer', enabled=False, actor='admin')
    current = (await client.get(path, headers=headers)).json()['case']
    assert current['owner_id'] == member['id'] and current['owner_enabled'] is False
    # 이전 배정의 계정 연결을 보존하면서 인계 메모·처리 상태를 갱신할 수 있다.
    assert (await client.put(path, headers=headers,
        json=handover(owner_id=member['id'], expected_version=1, status='closed'))).status_code == 200
    result = await client.put(path, headers=headers,
        json=handover(owner_id=actor['uid'], expected_version=2, status='investigating'))
    assert result.status_code == 200
    assert result.json()['case']['owner_id'] == actor['uid']
    assert [r['owner_id'] for r in result.json()['history']] == [actor['uid'], member['id'], member['id']]


@pytest.mark.asyncio
async def test_display_name_does_not_imply_account_assignment(managed_case, db):
    client, users, actor, headers, event_id = await case_setup(managed_case)
    member = await users.create('same-label', PASSWORD, 'viewer', 'admin')
    assert (await client.put(f'/api/events/{event_id}/case', headers=headers,
        json=handover(owner='same-label'))).status_code == 200
    linked = await client.get('/api/events', headers=headers, params={'case_owner_id': member['id']})
    assert linked.json()['total'] == 0
    named = await client.get('/api/events', headers=headers, params={'case_owner': 'same-label'})
    assert named.json()['total'] == 1 and named.json()['events'][0]['case_owner_id'] is None
    assert (await client.get('/api/events/export', headers=headers,
        params={'case_owner_id': member['id']})).json()['total'] == 0
    current = (await client.get(f'/api/events/{event_id}/case', headers=headers)).json()['case']
    assert current['owner_id'] is None


@pytest.mark.asyncio
async def test_changed_author_is_rejected_before_workflow_commit(managed_case, db):
    client, users, actor, headers, event_id = await case_setup(managed_case)
    await users.reset_password(actor['uid'], 1, 'ChangedAuthorPassword-2026', 'admin')
    with pytest.raises(ReviewConflict, match='actor_account_changed'):
        await CaseWorkflows(db).save(event_id, CaseRequest(**handover(owner_id=actor['uid'])),
            'admin', actor['uid'], 1)
    assert await db.pool.fetchval('SELECT count(*) FROM case_workflows') == 0


@pytest.mark.asyncio
async def test_assignment_choices_are_one_complete_snapshot_without_hashes(managed_case, db):
    client, users, actor, headers, event_id = await case_setup(managed_case)
    await db.pool.execute("""INSERT INTO user_accounts(id,username,password_hash,role,changed_by)
        SELECT gen_random_uuid(),'directory-'||n,password_hash,'viewer','fixture'
        FROM user_accounts CROSS JOIN generate_series(1,101) n WHERE username='admin'""")
    response = await client.get('/api/users?limit=1000', headers=headers)
    assert response.status_code == 200
    assert response.json()['total'] == len(response.json()['users']) == 102
    assert 'password' not in response.text and '$2b$' not in response.text
    assert (await client.get('/api/users?offset=1001', headers=headers)).status_code == 422
