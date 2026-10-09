"""사건 담당자·인계 이력의 실제 저장 및 권한 계약."""
import asyncio
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest

from tests.test_web.test_business_reviews import review_case
from netwatcher.ingest.repository import EveRepository
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager


def change(**values):
    return {'owner': '보안 담당자', 'status': 'investigating', 'note': '백업 담당자에게 통신 상대를 확인해야 합니다',
            'expected_version': 0} | values


def case_path(review_case):
    return review_case[1].replace('/business-review', '/case')


@pytest.mark.asyncio
async def test_owner_status_handover_history_preserve_original_event(db, review_case):
    client, _, event_id = review_case
    path = case_path(review_case)
    initial = (await client.get(path)).json()
    assert initial['case']['version'] == 0 and initial['history'] == []
    first = await client.put(path, json=change())
    assert first.status_code == 200, first.text
    second = await client.put(path, json=change(owner='야간 담당자', status='closed',
                                               note='상대 주소와 정상 백업 작업을 확인했습니다', expected_version=1))
    assert second.status_code == 200, second.text
    result = (await client.get(path)).json()
    assert result['case']['owner'] == '야간 담당자'
    assert result['case']['status'] == 'closed'
    assert [row['version'] for row in result['history']] == [2, 1]
    assert result['history'][1]['note'] == change()['note']
    assert await db.pool.fetchval('SELECT severity FROM events WHERE id=$1', event_id) == 'CRITICAL'
    assert await db.pool.fetchval('SELECT count(*) FROM business_reviews') == 0
    audit = await db.pool.fetch('SELECT action,details FROM audit_log')
    assert len(audit) == 6
    assert change()['note'] not in str(audit)
    assert {row['action'] for row in audit} == {'authorized_intent', 'change_prepared', 'api_mutation'}
    assert change()['note'] == (await db.pool.fetchval('SELECT note FROM case_history WHERE version=1'))


@pytest.mark.asyncio
async def test_concurrent_handover_does_not_overwrite(db, review_case):
    client, _, _ = review_case
    path = case_path(review_case)
    results = await asyncio.gather(client.put(path, json=change()), client.put(path, json=change(owner='다른 담당자')))
    assert sorted(result.status_code for result in results) == [200, 409]
    assert await db.pool.fetchval('SELECT count(*) FROM case_history') == 1
    stale = await client.put(path, json=change(status='closed'))
    assert stale.status_code == 409 and stale.json()['detail'] == 'version_changed'


@pytest.mark.asyncio
async def test_audit_failure_prevents_handover(db, review_case):
    client, _, _ = review_case
    await db.pool.execute('DROP TABLE audit_log')
    result = await client.put(case_path(review_case), json=change())
    assert result.status_code == 503
    assert await db.pool.fetchval('SELECT count(*) FROM case_history') == 0


@pytest.mark.asyncio
async def test_history_failure_rolls_back_owner_change(db, review_case):
    client, _, _ = review_case
    await db.pool.execute("ALTER TABLE case_history ADD CONSTRAINT reject_note CHECK(note <> '백업 담당자에게 통신 상대를 확인해야 합니다')")
    result = await client.put(case_path(review_case), json=change())
    assert result.status_code == 503
    assert await db.pool.fetchval('SELECT count(*) FROM case_workflows') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('values', [{'owner':'bad\nowner'}, {'note':'   '}, {'status':'invalid'},
                                   {'note':'text\x00private'}, {'owner':'a'*129}, {'expected_version':-1}])
async def test_invalid_handover_is_rejected(db, review_case, values):
    client, _, _ = review_case
    assert (await client.put(case_path(review_case), json=change(**values))).status_code == 422
    assert await db.pool.fetchval('SELECT count(*) FROM case_workflows') == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status', [(None,401), ('viewer',403), ('analyst',403), ('admin',200)])
async def test_handover_requires_admin(db, review_case, monkeypatch, role, status):
    monkeypatch.delenv('NETWATCHER_JWT_SECRET', raising=False)
    client, _, _ = review_case
    secret = secrets.token_hex(32)
    client._transport.app.state.auth_manager = AuthManager(Config({'auth': {'enabled':True,
        'jwt_secret':secret,'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers = {}
    if role:
        token = jwt.encode({'sub':'case-operator','role':role,
            'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
        headers['Authorization'] = 'Bearer '+token
    readable = await client.get(case_path(review_case), headers=headers)
    assert readable.status_code == (401 if role is None else 200)
    result = await client.put(case_path(review_case), json=change(),headers=headers)
    assert result.status_code == status
    assert await db.pool.fetchval('SELECT count(*) FROM case_history') == int(status == 200)


@pytest.mark.asyncio
async def test_retention_removes_case_and_history(db, review_case):
    client, _, _ = review_case
    assert (await client.put(case_path(review_case), json=change())).status_code == 200
    await db.pool.execute("UPDATE eve_records SET received_at=NOW()-interval '40 days'")
    assert await EveRepository(db).prune('test','office',days=30) == 2
    assert await db.pool.fetchval('SELECT count(*) FROM case_workflows') == 0
    assert await db.pool.fetchval('SELECT count(*) FROM case_history') == 0


@pytest.mark.asyncio
async def test_history_pagination_does_not_skip_entries(db, review_case):
    client, _, event_id = review_case
    assert (await client.put(case_path(review_case),json=change())).status_code == 200
    await db.pool.execute('UPDATE case_workflows SET version=52')
    await db.pool.execute('''INSERT INTO case_history(event_id,version,owner,status,note,actor,updated_at)
        SELECT $1,v,'operator','investigating','historical note','admin',NOW() FROM generate_series(2,52) v''',event_id)
    first = (await client.get(case_path(review_case))).json()
    assert [row['version'] for row in first['history']] == list(range(52,2,-1))
    assert first['next_before_version'] == 3
    second = (await client.get(case_path(review_case)+'?before_version=3')).json()
    assert [row['version'] for row in second['history']] == [2,1]
    assert second['next_before_version'] is None


@pytest.mark.asyncio
async def test_history_capacity_preserves_existing_case(db, review_case):
    client, _, _ = review_case
    assert (await client.put(case_path(review_case),json=change())).status_code == 200
    await db.pool.execute('UPDATE case_workflows SET version=1000')
    result = await client.put(case_path(review_case),json=change(expected_version=1000,status='closed'))
    assert result.status_code == 409 and result.json()['detail'] == 'history_capacity'
    assert await db.pool.fetchval('SELECT status FROM case_workflows') == 'investigating'


@pytest.mark.asyncio
async def test_missing_event_is_404(review_case):
    client, _, event_id = review_case
    path = case_path(review_case).replace(f'/{event_id}/',f'/{event_id+100000}/')
    assert (await client.get(path)).status_code == 404


@pytest.mark.asyncio
async def test_event_repository_retention_removes_notes_and_reviews(db, event_repo, review_case):
    client, review_path, event_id = review_case
    assert (await client.put(case_path(review_case), json=change())).status_code == 200
    assert (await client.put(review_path, json={'decision':'investigate','note':'원래 경보 조사 필요',
                                               'expected_version':0})).status_code == 200
    await db.pool.execute("UPDATE events SET timestamp=NOW()-interval '40 days'")
    assert await event_repo.delete_older_than(30) == 1
    for table in ('case_workflows','case_history','business_reviews'):
        assert await db.pool.fetchval(f'SELECT count(*) FROM {table}') == 0


@pytest.mark.asyncio
async def test_event_retention_failure_preserves_case_and_review(db, event_repo, review_case):
    import asyncpg
    client, review_path, event_id = review_case
    assert (await client.put(case_path(review_case), json=change())).status_code == 200
    assert (await client.put(review_path, json={'decision':'investigate','note':'원래 경보 조사 필요',
                                               'expected_version':0})).status_code == 200
    await db.pool.execute("UPDATE events SET timestamp=NOW()-interval '40 days'")
    await db.pool.execute('CREATE TABLE retention_guard(event_id BIGINT REFERENCES case_workflows(event_id))')
    await db.pool.execute('INSERT INTO retention_guard VALUES($1)',event_id)
    with pytest.raises(asyncpg.ForeignKeyViolationError):
        await event_repo.delete_older_than(30)
    for table in ('events','case_workflows','case_history','business_reviews'):
        assert await db.pool.fetchval(f'SELECT count(*) FROM {table}') == 1
