"""수동·CSV 승인 작업의 원자적 등록과 사건 범위·취소 계약."""
import csv
import io
from datetime import datetime,timedelta,timezone

import pytest

from tests.test_web.test_business_reviews import review_case
from netwatcher.web.routes.work_schedules import WorkRequest


def job(**changes):
    now=datetime.now(timezone.utc)
    return {'title':'야간 백업 작업','kind':'backup','owner':'백업 담당자','ticket':'CHG-001',
        'note':'승인한 백업 상대와 시간 범위를 확인했습니다','source_ip':'192.0.2.10',
        'source_mac':'02:00:00:00:00:10','dest_ip':'198.51.100.20','protocol':'TCP','dest_port':443,
        'starts_at':(now-timedelta(hours=1)).isoformat(),'ends_at':(now+timedelta(hours=1)).isoformat(),
        'max_flow_bytes':4096} | changes


def csv_body(rows):
    output=io.StringIO();writer=csv.DictWriter(output,fieldnames=WorkRequest.model_fields)
    writer.writeheader();writer.writerows(rows)
    return {'csv':output.getvalue()}


@pytest.mark.asyncio
async def test_register_deduplicate_and_link_preserve_alert(db,review_case):
    client,_,event_id=review_case
    body=job()
    result=await client.post('/api/work-schedules',json=body)
    assert result.status_code==200,result.text
    schedule_id=result.json()['created_ids'][0]
    repeated=await client.post('/api/work-schedules',json=body)
    assert repeated.json()['created_ids']==[] and repeated.json()['existing_count']==1
    path=f'/api/events/{event_id}/work-schedule'
    matches=(await client.get(path)).json()
    assert matches['matches'][0]['content']['ticket']=='CHG-001'
    result=await client.put(path,json={'schedule_id':schedule_id,'expected_version':0})
    assert result.status_code==200 and result.json()['current']['state']=='matched'
    assert result.json()['current']['schedule']['content']['owner']=='백업 담당자'
    assert await db.pool.fetchval('SELECT severity FROM events WHERE id=$1',event_id)=='CRITICAL'
    assert await db.pool.fetchval('SELECT count(*) FROM business_reviews')==0
    audit=await db.pool.fetch('SELECT action,details FROM audit_log')
    assert {row['action'] for row in audit}=={'authorized_intent','change_prepared','api_mutation'}
    assert body['note'] not in str(audit)


@pytest.mark.asyncio
async def test_csv_atomic_validation_and_idempotence(db,review_case):
    client,_,_=review_case
    rows=[job(),job(ticket='CHG-002')]
    invalid=rows+[job(dest_ip='not an address')]
    result=await client.post('/api/work-schedules/import',json=csv_body(invalid))
    assert result.status_code==422
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==0
    body=csv_body(rows+[rows[0]])
    result=await client.post('/api/work-schedules/import',json=body)
    assert result.status_code==200,result.text
    assert len(result.json()['created_ids'])==2 and result.json()['duplicate_rows']==1
    result=await client.post('/api/work-schedules/import',json=body)
    assert result.json()['existing_count']==2
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==2


@pytest.mark.asyncio
async def test_revoke_preserves_record_and_invalidates_link(db,review_case):
    client,_,event_id=review_case
    schedule_id=(await client.post('/api/work-schedules',json=job())).json()['created_ids'][0]
    path=f'/api/events/{event_id}/work-schedule'
    assert (await client.put(path,json={'schedule_id':schedule_id,'expected_version':0})).status_code==200
    revoked=await client.post(f'/api/work-schedules/{schedule_id}/revoke',json={'expected_version':1,'note':'백업 일정 취소 확인'})
    assert revoked.status_code==200
    result=(await client.get(path)).json()
    assert result['current']['state']=='revoked' and result['matches']==[]
    assert result['current']['schedule']['content']['ticket']=='CHG-001'
    assert (await client.put(path,json={'schedule_id':schedule_id,'expected_version':1})).status_code==409


@pytest.mark.asyncio
@pytest.mark.parametrize('changes',[{'source_mac':'02:00:00:00:00:11'},{'dest_ip':'198.51.100.21'},
 {'dest_port':8443},{'protocol':'UDP'},{'starts_at':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
 'ends_at':(datetime.now(timezone.utc)+timedelta(days=1,hours=1)).isoformat()}])
async def test_scope_mismatch_prevents_link(review_case,changes):
    client,_,event_id=review_case
    schedule_id=(await client.post('/api/work-schedules',json=job(**changes))).json()['created_ids'][0]
    path=f'/api/events/{event_id}/work-schedule'
    result=await client.put(path,json={'schedule_id':schedule_id,'expected_version':0})
    assert result.status_code==409,result.text
    assert result.json()['detail']=='schedule_scope_mismatch'


@pytest.mark.asyncio
async def test_audit_failure_prevents_schedule_registration(db,review_case):
    client,_,_=review_case
    await db.pool.execute('DROP TABLE audit_log')
    assert (await client.post('/api/work-schedules',json=job())).status_code==503
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==0


@pytest.mark.asyncio
async def test_normal_review_records_work_and_reopens_when_cancelled(db,review_case):
    from tests.test_web.test_business_reviews import decision
    client,review_path,event_id=review_case
    schedule_id=(await client.post('/api/work-schedules',json=job())).json()['created_ids'][0]
    path=f'/api/events/{event_id}/work-schedule'
    assert (await client.put(path,json={'schedule_id':schedule_id,'expected_version':0})).status_code==200
    response=await client.put(review_path,json=decision())
    assert response.status_code==200,response.text
    scope=response.json()['review']['scope']['work_schedule']
    assert scope['id']==schedule_id and scope['content']['ticket']=='CHG-001'
    assert (await client.post(f'/api/work-schedules/{schedule_id}/revoke',json={'expected_version':1,'note':'일정 취소 확인'})).status_code==200
    result=(await client.get(review_path)).json()
    assert result['state']=='needs_review' and result['reason']=='work_cancelled'
    historical=(await client.get(review_path+'/history')).json()['history'][0]
    assert historical['scope']['work_schedule']==scope


@pytest.mark.asyncio
async def test_work_byte_limit_and_relinked_schedule_require_review(review_case):
    from tests.test_web.test_business_reviews import decision
    client,review_path,event_id=review_case
    schedule_id=(await client.post('/api/work-schedules',json=job(max_flow_bytes=2048))).json()['created_ids'][0]
    path=f'/api/events/{event_id}/work-schedule'
    assert (await client.put(path,json={'schedule_id':schedule_id,'expected_version':0})).status_code==200
    response=await client.put(review_path,json=decision())
    assert response.status_code==409 and response.json()['detail']=='work_volume_limit'
    assert (await client.put(review_path,json=decision(max_bytes=2048))).status_code==200
    next_id=(await client.post('/api/work-schedules',json=job(ticket='CHG-002'))).json()['created_ids'][0]
    assert (await client.put(path,json={'schedule_id':next_id,'expected_version':1})).status_code==200
    assert (await client.get(review_path)).json()['reason']=='work_link_changed'


@pytest.mark.asyncio
@pytest.mark.parametrize('body',[{'csv':'"unterminated'}, {'csv':'title,title\nx,y'},
                                  {'csv':'title\nname'}, {'csv':'a'*131073}])
async def test_csv_format_and_capacity_fail_without_writes(db,review_case,body):
    client,_,_=review_case
    assert (await client.post('/api/work-schedules/import',json=body)).status_code==422
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==0


@pytest.mark.asyncio
async def test_csv_row_limit_and_utf8_byte_limit(db,review_case):
    client,_,_=review_case
    assert (await client.post('/api/work-schedules/import',json=csv_body([job()]*101))).status_code==422
    assert (await client.post('/api/work-schedules/import',json={'csv':'가'*50000})).status_code==422
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==0


@pytest.mark.asyncio
async def test_old_unlinked_work_is_pruned_but_linked_work_is_kept(db,review_case):
    client,_,event_id=review_case
    now=datetime.now(timezone.utc)
    old=job(starts_at=(now-timedelta(days=100,hours=1)).isoformat(),ends_at=(now-timedelta(days=100)).isoformat())
    linked_id=(await client.post('/api/work-schedules',json=old)).json()['created_ids'][0]
    await db.pool.execute('INSERT INTO event_work_links(event_id,schedule_id,version,actor) VALUES($1,$2::text::uuid,1,$3)',event_id,linked_id,'operator')
    free=job(ticket='OLD-UNLINKED',starts_at=old['starts_at'],ends_at=old['ends_at'])
    free_id=(await client.post('/api/work-schedules',json=free)).json()['created_ids'][0]
    assert (await client.post('/api/work-schedules',json=job())).status_code==200
    assert await db.pool.fetchval('SELECT EXISTS(SELECT 1 FROM work_schedules WHERE id=$1::text::uuid)',linked_id)
    assert not await db.pool.fetchval('SELECT EXISTS(SELECT 1 FROM work_schedules WHERE id=$1::text::uuid)',free_id)


@pytest.mark.asyncio
async def test_link_retention_deletes_event_association(db,review_case):
    from netwatcher.ingest.repository import EveRepository
    client,_,event_id=review_case
    schedule_id=(await client.post('/api/work-schedules',json=job())).json()['created_ids'][0]
    assert (await client.put(f'/api/events/{event_id}/work-schedule',json={'schedule_id':schedule_id,'expected_version':0})).status_code==200
    await db.pool.execute("UPDATE eve_records SET received_at=NOW()-interval '40 days'")
    await EveRepository(db).prune('test','office',days=30)
    assert await db.pool.fetchval('SELECT count(*) FROM event_work_links')==0


@pytest.mark.asyncio
async def test_csv_database_failure_rolls_back_entire_import(db,review_case):
    client,_,_=review_case
    await db.pool.execute("ALTER TABLE work_schedules ADD CONSTRAINT reject_second CHECK(content->>'ticket'<>'CHG-002')")
    assert (await client.post('/api/work-schedules/import',json=csv_body([job(),job(ticket='CHG-002')]))).status_code==503
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==0


@pytest.mark.asyncio
async def test_matching_schedules_are_paginated_without_loss(review_case):
    client,_,event_id=review_case
    rows=[job(ticket=f'CHG-{index:03d}',source_mac=None,dest_port=None) for index in range(55)]
    assert (await client.post('/api/work-schedules/import',json=csv_body(rows))).status_code==200
    path=f'/api/events/{event_id}/work-schedule'
    first=(await client.get(path)).json()
    second=(await client.get(path,params={'offset':50})).json()
    assert first['total_matches']==55 and len(first['matches'])==50 and len(second['matches'])==5
    assert len({row['id'] for row in first['matches']+second['matches']})==55


@pytest.mark.asyncio
async def test_schedule_capacity_never_partially_imports(db,review_case):
    client,_,_=review_case
    assert (await client.post('/api/work-schedules',json=job())).status_code==200
    await db.pool.execute("""INSERT INTO work_schedules(id,fingerprint,content,starts_at,ends_at,actor)
        SELECT md5(v::text)::uuid,md5(v::text)||md5(v::text),content,starts_at,ends_at,'capacity test'
        FROM work_schedules CROSS JOIN generate_series(1,1999) v""")
    response=await client.post('/api/work-schedules/import',json=csv_body([job(ticket='NEW-001'),job(ticket='NEW-002')]))
    assert response.status_code==409 and response.json()['detail']=='schedule_capacity'
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==2000


@pytest.mark.asyncio
@pytest.mark.parametrize('changes',[{'max_flow_bytes':True},{'dest_port':True},{'source_mac':'invalid'},
 {'starts_at':'2026-10-08T01:00:00'},{'starts_at':0},{'owner':'  '},{'ends_at':'2026-01-01T00:00:00Z'}])
async def test_invalid_manual_schedule_is_rejected(db,review_case,changes):
    client,_,_=review_case
    assert (await client.post('/api/work-schedules',json=job(**changes))).status_code==422
    assert await db.pool.fetchval('SELECT count(*) FROM work_schedules')==0


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',403),('analyst',403),('admin',200)])
async def test_schedule_changes_require_admin(review_case,monkeypatch,role,status):
    import secrets
    import bcrypt,jwt
    from netwatcher.utils.config import Config
    from netwatcher.web.auth import AuthManager
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    client,_,_=review_case
    secret=secrets.token_hex(32)
    client._transport.app.state.auth_manager=AuthManager(Config({'auth':{'enabled':True,'jwt_secret':secret,
        'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers={}
    if role:headers['Authorization']='Bearer '+jwt.encode({'sub':'work-operator','role':role,
        'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
    assert (await client.get('/api/work-schedules',headers=headers)).status_code==(401 if role is None else 200)
    assert (await client.post('/api/work-schedules',json=job(),headers=headers)).status_code==status
    assert (await client.post('/api/work-schedules/import',json=csv_body([job()]),headers=headers)).status_code==status
