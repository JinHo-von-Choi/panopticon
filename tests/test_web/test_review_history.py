"""판정 변경 뒤에도 당시 근거·범위·수명이 보존되는지 검증한다."""
import pytest

from tests.test_web.test_business_reviews import review_case, decision
from netwatcher.ingest.repository import EveRepository


@pytest.mark.asyncio
async def test_changed_decision_keeps_original_reason_scope_and_expiry(db,review_case):
    client,path,event_id = review_case
    original = await client.put(path,json=decision())
    assert original.status_code == 200
    first = original.json()['review']
    changed = await client.put(path,json=decision(decision='investigate',note='상대의 업무 역할을 추가 확인합니다',expected_version=1))
    assert changed.status_code == 200
    history = (await client.get(path+'/history')).json()['history']
    assert [row['version'] for row in history] == [2,1]
    assert history[1] == first
    assert history[0]['decision'] == 'investigate'
    assert history[0]['expires_at'] is None
    assert await db.pool.fetchval('SELECT severity FROM events WHERE id=$1',event_id) == 'CRITICAL'


@pytest.mark.asyncio
async def test_history_failure_rolls_back_latest_review(db,review_case):
    client,path,_ = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    await db.pool.execute("ALTER TABLE business_review_history ADD CONSTRAINT reject_new CHECK(version<2)")
    result = await client.put(path,json=decision(decision='investigate',expected_version=1))
    assert result.status_code == 503
    assert await db.pool.fetchval('SELECT version FROM business_reviews') == 1
    assert await db.pool.fetchval('SELECT count(*) FROM business_review_history') == 1


@pytest.mark.asyncio
async def test_stale_review_does_not_append_false_history(db,review_case):
    client,path,_ = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    assert (await client.put(path,json=decision())).status_code == 409
    assert await db.pool.fetchval('SELECT count(*) FROM business_review_history') == 1


@pytest.mark.asyncio
async def test_history_retained_during_reopen_and_removed_with_event(db,review_case):
    client,path,_ = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    await db.pool.execute("UPDATE business_reviews SET expires_at=NOW()-interval '1 second'")
    assert (await client.get(path)).json()['state'] == 'needs_review'
    assert (await client.get(path+'/history')).json()['history'][0]['decision'] == 'expected_backup'
    await db.pool.execute("UPDATE eve_records SET received_at=NOW()-interval '40 days'")
    await EveRepository(db).prune('test','office',days=30)
    assert await db.pool.fetchval('SELECT count(*) FROM business_review_history') == 0


@pytest.mark.asyncio
async def test_history_pages_preserve_all_versions(db,review_case):
    client,path,event_id = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    await db.pool.execute('''INSERT INTO business_review_history
        SELECT event_id,v,decision,note,actor,scope,reviewed_at,expires_at
        FROM business_reviews CROSS JOIN generate_series(2,52) v''')
    page = (await client.get(path+'/history')).json()
    assert [row['version'] for row in page['history']] == list(range(52,2,-1))
    assert page['next_before_version'] == 3
    page = (await client.get(path+'/history?before_version=3')).json()
    assert [row['version'] for row in page['history']] == [2,1]
    assert page['next_before_version'] is None


@pytest.mark.asyncio
async def test_history_capacity_refuses_overwrite(db,review_case):
    client,path,_ = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    await db.pool.execute('''INSERT INTO business_review_history
        SELECT event_id,v,decision,note,actor,scope,reviewed_at,expires_at
        FROM business_reviews CROSS JOIN generate_series(2,1000) v''')
    result = await client.put(path,json=decision(decision='investigate',expected_version=1))
    assert result.status_code == 409 and result.json()['detail'] == 'history_capacity'
    assert await db.pool.fetchval('SELECT decision FROM business_reviews') == 'expected_backup'


@pytest.mark.asyncio
async def test_missing_event_history_returns_404(review_case):
    client,path,event_id = review_case
    path = path.replace(f'/{event_id}/',f'/{event_id+100000}/')
    assert (await client.get(path+'/history')).status_code == 404


@pytest.mark.asyncio
async def test_migration_preserves_only_latest_available_legacy_decision(db,review_case):
    import importlib.util
    from pathlib import Path
    from unittest.mock import patch
    client,path,_ = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    response = await client.put(path,json=decision(decision='investigate',note='갱신 전 보존된 최신 근거',expected_version=1))
    original = response.json()['review']
    await db.pool.execute('DROP TABLE business_review_history')
    migration_path = Path(__file__).resolve().parents[2]/'alembic/versions/024_business_review_history.py'
    spec = importlib.util.spec_from_file_location('review_history_migration',migration_path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    statements = []
    with patch.object(migration.op,'execute',side_effect=statements.append):
        migration.upgrade()
    for statement in statements:
        await db.pool.execute(statement)
    history = (await client.get(path+'/history')).json()['history']
    assert history == [original]
    assert (await client.put(path,json=decision(decision='insufficient_evidence',expected_version=2))).status_code == 200
    assert [row['version'] for row in (await client.get(path+'/history')).json()['history']] == [3,2]


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',200),('analyst',200),('admin',200)])
async def test_history_viewer_authorization(review_case,monkeypatch,role,status):
    import secrets
    from datetime import datetime,timedelta,timezone
    import bcrypt,jwt
    from netwatcher.utils.config import Config
    from netwatcher.web.auth import AuthManager
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    client,path,_ = review_case
    secret = secrets.token_hex(32)
    client._transport.app.state.auth_manager = AuthManager(Config({'auth':{'enabled':True,
        'jwt_secret':secret,'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers = {}
    if role:
        headers['Authorization']='Bearer '+jwt.encode({'sub':'history-viewer','role':role,
            'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
    assert (await client.get(path+'/history',headers=headers)).status_code == status


@pytest.mark.asyncio
async def test_review_snapshot_keeps_confirmed_asset_role_after_reassignment(db,device_repo,review_case):
    from datetime import datetime,timedelta,timezone
    client,path,_ = review_case
    assert (await client.put(path,json=decision())).status_code == 200
    now = datetime.now(timezone.utc)
    assert await device_repo.confirm_context('02:00:00:00:00:10','192.0.2.10',1,
        {'role':'server','confirmed_by':'new operator','confirmed_at':now.isoformat(),
         'expires_at':(now+timedelta(days=7)).isoformat()})
    assert (await client.get(path)).json()['reason'] == 'ownership_changed'
    history = (await client.get(path+'/history')).json()['history']
    assert history[0]['scope']['asset_context']['role'] == 'backup'
    assert history[0]['scope']['asset_context']['confirmed_by'] == 'operator'


@pytest.mark.asyncio
@pytest.mark.parametrize('cursor',[0,-1,2**63])
async def test_invalid_history_cursor_is_422(review_case,cursor):
    client,path,_ = review_case
    for route in (path+'/history',path.replace('/business-review','/case')):
        assert (await client.get(route,params={'before_version':cursor})).status_code == 422
