"""같은 조건의 이전 경보를 비교하되 판정은 개별 사건에 유지한다."""
from datetime import datetime,timedelta,timezone
import secrets

import bcrypt
import jwt
import pytest

from tests.test_web.test_business_reviews import review_case,decision
from tests.test_web.test_event_groups import add_alerts,template
from tests.test_web.test_case_workflows import change
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager


def previous_time(row):
    return datetime.fromisoformat(row['timestamp']).astimezone(timezone.utc).replace(minute=0,second=0,microsecond=0)-timedelta(hours=1)


@pytest.mark.asyncio
async def test_previous_normal_review_and_handover_do_not_approve_current_event(db,review_case):
    client,path,event_id=review_case
    row=await template(db,event_id);past=previous_time(row).isoformat()
    await add_alerts(db,row,[{'timestamp':past,'flow_id':999},
        {'timestamp':past,'flow_id':999,'event_type':'flow','flow':{'bytes_toserver':1000,'bytes_toclient':500}}])
    old=await db.pool.fetchval('SELECT id FROM events WHERE id!=$1',event_id)
    note='백업 작업을 확인했습니다. <script>unsafe</script>'
    assert (await client.put(f'/api/events/{old}/business-review',json=decision(note=note))).status_code==200
    assert (await client.put(f'/api/events/{old}/case',json=change(status='closed',note='다음 담당자에게 결과를 인계합니다'))).status_code==200
    response=await client.get(f'/api/events/{event_id}/similar')
    assert response.status_code==200,response.text
    data=response.json()
    assert data['view']=='previous_same_scope' and data['total']==1
    previous=data['events'][0]
    assert previous['id']==old and previous['recorded_decision']=='expected_backup'
    assert previous['review_note']==note and previous['owner']==change()['owner']
    assert previous['status']=='closed' and previous['recorded_asset_context']['role']=='backup'
    assert previous['handover_note']=='다음 담당자에게 결과를 인계합니다'
    assert (await client.get(path)).json()['state']=='unreviewed'
    assert await db.pool.fetchval('SELECT count(*) FROM business_reviews')==1
    assert response.headers['cache-control']=='no-store'


@pytest.mark.asyncio
@pytest.mark.parametrize('changes',[{'src_ip':'192.0.2.12'},{'dest_ip':'198.51.100.22'},
    {'dest_port':8443},{'proto':'UDP'},{'ether':{'src_mac':'02:00:00:00:00:11'}},
    {'alert':{'signature_id':101,'severity':1}},{'alert':{'signature_id':100,'severity':1,'rev':2}}])
async def test_other_scope_is_not_presented_as_previous_same_condition(db,review_case,changes):
    client,_,event_id=review_case
    row=await template(db,event_id)
    await add_alerts(db,row,[{'timestamp':previous_time(row).isoformat()}|changes])
    assert (await client.get(f'/api/events/{event_id}/similar')).json()['total']==0


@pytest.mark.asyncio
async def test_previous_window_boundaries_and_pagination(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id)
    end=previous_time(row)+timedelta(hours=1);start=end-timedelta(days=1)
    await add_alerts(db,row,[{'timestamp':end.isoformat()}, {'timestamp':start.isoformat()},
        {'timestamp':(start-timedelta(seconds=1)).isoformat()}]+[{'timestamp':(end-timedelta(seconds=1)).isoformat()} for _ in range(55)])
    first=(await client.get(f'/api/events/{event_id}/similar?days=1')).json()
    second=(await client.get(f'/api/events/{event_id}/similar?days=1&offset=50')).json()
    assert first['total']==second['total']==56
    assert len(first['events'])==50 and len(second['events'])==6
    assert not {e['id'] for e in first['events']} & {e['id'] for e in second['events']}
    assert first['window']['start']==start.isoformat() and first['window']['end']==end.isoformat()


@pytest.mark.asyncio
async def test_missing_address_native_and_unknown_event_are_distinct(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id);row.pop('src_ip')
    await add_alerts(db,row,[{'timestamp':previous_time(row).isoformat()}])
    unknown=await db.pool.fetchval("SELECT event_id FROM eve_records WHERE record->>'src_ip' IS NULL")
    assert (await client.get(f'/api/events/{unknown}/similar')).json()=={'available':False,'reason':'addresses_required'}
    await db.pool.execute('DELETE FROM eve_records WHERE event_id=$1',event_id)
    assert (await client.get(f'/api/events/{event_id}/similar')).json()['reason']=='eve_alert_required'
    assert (await client.get('/api/events/9223372036854775807/similar')).status_code==404


@pytest.mark.asyncio
@pytest.mark.parametrize('query',['days=0','days=91','limit=101','offset=-1'])
async def test_previous_query_bounds(review_case,query):
    client,_,event_id=review_case
    assert (await client.get(f'/api/events/{event_id}/similar?{query}')).status_code==422


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',200),('analyst',200),('admin',200)])
async def test_previous_requires_authenticated_viewer(review_case,monkeypatch,role,status):
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    client,_,event_id=review_case;secret=secrets.token_hex(32)
    client._transport.app.state.auth_manager=AuthManager(Config({'auth':{'enabled':True,'jwt_secret':secret,
        'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers={}
    if role:
        headers['Authorization']='Bearer '+jwt.encode({'sub':'viewer','role':role,
            'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
    assert (await client.get(f'/api/events/{event_id}/similar',headers=headers)).status_code==status
