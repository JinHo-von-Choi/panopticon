"""보존 중인 전체 사건의 처리 상태와 판정 기한을 집계한다."""
from datetime import datetime, timedelta, timezone
import secrets

import bcrypt
import jwt
import pytest

from tests.test_web.test_business_reviews import review_case, decision
from tests.test_web.test_case_workflows import change, case_path
from netwatcher.investigation.priorities import InvestigationPriorities
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager


@pytest.mark.asyncio
async def test_all_retained_counts_and_categories_use_individual_state(db, review_case):
    client, path, event_id = review_case
    initial=(await client.get('/api/investigation/priorities')).json()
    assert initial['counts']=={'stored_events':1,'unclosed':1,'unassigned':1,'unreviewed':1,'expired':0,'recheck':None}
    assert initial['proposals_available'] is False and initial['pending_proposals'] is None
    assert initial['scope']=='all_retained_events'
    assert (await client.put(path,json=decision())).status_code==200
    assert (await client.put(case_path(review_case),json=change(status='closed'))).status_code==200
    await db.pool.execute("UPDATE business_reviews SET expires_at=NOW()-interval '1 second'")
    current=(await client.get('/api/investigation/priorities?category=expired')).json()
    assert current['counts']=={'stored_events':1,'unclosed':0,'unassigned':0,'unreviewed':0,'expired':1,'recheck':None}
    assert current['events'][0]['id']==event_id and current['events'][0]['status']=='closed'
    assert current['events'][0]['recorded_decision']=='expected_backup'
    assert await db.pool.fetchval('SELECT severity FROM events WHERE id=$1',event_id)=='CRITICAL'
    assert (await client.get(path)).json()['state']=='needs_review'


@pytest.mark.asyncio
async def test_counts_are_not_limited_to_latest_50_and_pagination_is_stable(db, review_case):
    client, _, event_id = review_case
    await db.pool.execute("""INSERT INTO events(engine,severity,title,timestamp)
        SELECT 'test','WARNING','Old retained event',NOW()-interval '40 days' FROM generate_series(1,55)""")
    first=(await client.get('/api/investigation/priorities')).json()
    second=(await client.get('/api/investigation/priorities?offset=50')).json()
    beyond=(await client.get('/api/investigation/priorities?offset=100')).json()
    assert first['total']==second['total']==beyond['total']==56
    assert first['events'][0]['id']==event_id
    assert len(first['events'])==50 and len(second['events'])==6 and beyond['events']==[]
    assert not {e['id'] for e in first['events']} & {e['id'] for e in second['events']}


@pytest.mark.asyncio
@pytest.mark.parametrize('params',[{'category':'normal'},{'limit':101},{'offset':-1}])
async def test_invalid_category_and_paging_are_rejected(review_case, params):
    client, _, _=review_case
    assert (await client.get('/api/investigation/priorities',params=params)).status_code==422


@pytest.mark.asyncio
async def test_expiry_only_applies_to_recorded_normal_decisions(db, review_case):
    client, path, _=review_case
    assert (await client.put(path,json=decision(decision='insufficient_evidence'))).status_code==200
    await db.pool.execute("UPDATE business_reviews SET expires_at=NOW()-interval '1 day'")
    response=await client.get('/api/investigation/priorities?category=expired')
    assert response.status_code==200
    assert response.json()['total']==0
    assert response.headers['cache-control']=='no-store'


@pytest.mark.asyncio
async def test_storage_failure_is_unknown_not_zero(db, review_case):
    client, _, _=review_case
    await db.pool.execute('DROP TABLE business_review_history; DROP TABLE business_reviews')
    assert (await client.get('/api/investigation/priorities')).status_code==503


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',200),('analyst',200),('admin',200)])
async def test_priority_requires_authenticated_viewer(review_case,monkeypatch,role,status):
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    client, _, _=review_case
    secret=secrets.token_hex(32)
    client._transport.app.state.auth_manager=AuthManager(Config({'auth':{'enabled':True,'jwt_secret':secret,
        'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers={}
    if role:
        headers['Authorization']='Bearer '+jwt.encode({'sub':'viewer','role':role,
            'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
    assert (await client.get('/api/investigation/priorities',headers=headers)).status_code==status


@pytest.mark.asyncio
async def test_pending_proposals_are_counted_only_when_feature_available(db, review_case):
    await db.pool.execute("""INSERT INTO config_proposals(engine,params,status)
        VALUES('test','{}'::jsonb,'pending'),('test','{}'::jsonb,'approved'),('test','{}'::jsonb,'pending')""")
    available=await InvestigationPriorities(db,proposals_available=True).get()
    assert available['proposals_available'] is True and available['pending_proposals']==2
    unavailable=await InvestigationPriorities(db).get()
    assert unavailable['proposals_available'] is False and unavailable['pending_proposals'] is None


@pytest.mark.asyncio
async def test_remote_priority_proposal_count_is_scoped_to_sensor(db, review_case):
    from uuid import uuid4
    await db.pool.execute("""INSERT INTO config_proposals(engine,params,status,sensor_id,sensor_owner,source_version)
        VALUES ('port_scan','{"threshold":10}'::jsonb,'pending','office',$1,$2),
               ('port_scan','{"threshold":10}'::jsonb,'pending','other-office',$1,$2),
               ('port_scan','{"threshold":10}'::jsonb,'pending',NULL,NULL,NULL)""", uuid4(), 'a'*64)
    result = await InvestigationPriorities(db, proposals_available=True, proposal_sensor_id='office').get()
    assert result['pending_proposals'] == 1
    result = await InvestigationPriorities(db, proposals_available=True, proposal_sensor_id='absent').get()
    assert result['pending_proposals'] == 0
    assert await db.pool.fetchval('SELECT count(*) FROM config_proposals') == 3


@pytest.mark.asyncio
async def test_valid_normal_review_is_not_a_recheck_and_is_read_only(db,review_case):
    client,path,_=review_case
    assert (await client.put(path,json=decision())).status_code==200
    history=await db.pool.fetchval('SELECT count(*) FROM business_review_history')
    data=(await client.get('/api/investigation/priorities?category=recheck')).json()
    assert data['recheck_evaluated'] is True and data['counts']['recheck']==data['total']==0
    assert data['events']==[]
    assert await db.pool.fetchval('SELECT count(*) FROM business_review_history')==history


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation,reason',[
    ("UPDATE business_reviews SET expires_at=NOW()-interval '1 second'",'expired'),
    ("UPDATE devices SET context_version=context_version+1",'ownership_changed'),
    ("UPDATE events SET dest_ip='198.51.100.21'",'communication_changed'),
    ("DELETE FROM eve_records WHERE event_type='flow'",'flow_evidence_missing'),
    ("UPDATE eve_records SET record=jsonb_set(record,'{details,bytes_toserver}','9000') WHERE event_type='flow'",'volume_exceeded'),
    ("UPDATE eve_records SET record=jsonb_set(record,'{original_ref,sha256}','\"changed\"') WHERE event_type='flow'",'flow_evidence_changed'),
])
async def test_recheck_reason_matches_single_event(db,review_case,mutation,reason):
    client,path,event_id=review_case
    assert (await client.put(path,json=decision())).status_code==200
    await db.pool.execute(mutation)
    response=await client.get('/api/investigation/priorities?category=recheck')
    assert response.status_code==200,response.text
    data=response.json()
    assert data['total']==1 and data['events'][0]['id']==event_id
    assert data['events'][0]['review_state']=='needs_review'
    assert data['events'][0]['review_reason']==(await client.get(path)).json()['reason']==reason
    assert await db.pool.fetchval('SELECT decision FROM business_reviews')=='expected_backup'


@pytest.mark.asyncio
async def test_cancelled_work_is_rechecked_without_expiry(db,review_case):
    from tests.test_web.test_work_schedules import job
    client,path,event_id=review_case
    schedule=(await client.post('/api/work-schedules',json=job())).json()['created_ids'][0]
    assert (await client.put(f'/api/events/{event_id}/work-schedule',json={'schedule_id':schedule,'expected_version':0})).status_code==200
    assert (await client.put(path,json=decision())).status_code==200
    assert (await client.post(f'/api/work-schedules/{schedule}/revoke',json={'expected_version':1,'note':'승인 작업이 취소됐습니다'})).status_code==200
    data=(await client.get('/api/investigation/priorities?category=recheck')).json()
    assert data['counts']['expired']==0 and data['total']==1
    assert data['events'][0]['review_reason']=='work_cancelled'


@pytest.mark.asyncio
async def test_recheck_capacity_refuses_partial_count_but_other_queues_work(db,review_case):
    client,path,_=review_case
    assert (await client.put(path,json=decision())).status_code==200
    await db.pool.execute("""WITH added AS (
        INSERT INTO events(engine,severity,title,timestamp)
        SELECT 'test','INFO','Retained normal event',NOW() FROM generate_series(1,1000) RETURNING id
    ) INSERT INTO business_reviews(event_id,version,decision,note,actor,scope,reviewed_at,expires_at)
        SELECT id,1,'expected_backup','Stored normal decision','operator','{}'::jsonb,NOW()-interval '1 hour',NOW()-interval '1 second'
        FROM added""")
    response=await client.get('/api/investigation/priorities?category=recheck')
    assert response.status_code==413 and response.json()['detail']=='review_evaluation_capacity'
    data=(await client.get('/api/investigation/priorities')).json()
    assert data['total']==1001 and data['recheck_evaluated'] is False and data['counts']['recheck'] is None


@pytest.mark.asyncio
async def test_review_shared_snapshot_preserves_identity_at_snapshot_time(db,review_case):
    from netwatcher.investigation.reviews import BusinessReviews
    client,path,event_id=review_case
    assert (await client.put(path,json=decision())).status_code==200
    async with db.pool.acquire() as conn,conn.transaction(isolation='repeatable_read',readonly=True):
        snapshot=await conn.fetchval('SELECT transaction_timestamp()')
        await conn.fetchval('SELECT count(*) FROM devices')
        await db.pool.execute('UPDATE devices SET context_version=context_version+1')
        at_snapshot=await BusinessReviews(db).get(event_id,connection=conn,now=datetime.fromisoformat(snapshot))
        assert at_snapshot['state']=='normal_confirmed'
    assert (await client.get(path)).json()['reason']=='ownership_changed'
