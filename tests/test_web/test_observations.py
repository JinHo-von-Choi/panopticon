"""첫 관측은 전체 보존 로그로 비교하며 장치 신원을 추정하지 않는다."""
from datetime import datetime,timedelta,timezone
import secrets

import bcrypt
import jwt
import pytest

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_event_groups import add_alerts,template
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager


@pytest.mark.asyncio
async def test_old_history_prevents_false_new_address_and_peer(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id)
    await add_alerts(db,row,[{'timestamp':(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()}])
    for kind in ('addresses','peers'):
        response=await client.get('/api/investigation/observations',params={'kind':kind})
        assert response.status_code==200,response.text
        data=response.json()
        assert data['total']==0 and data['observations']==[]
        assert data['identity_confirmed'] is False and data['scope']=='all_retained_eve_records'
        assert response.headers['cache-control']=='no-store'
        assert data['baseline']['retained_records']==3


@pytest.mark.asyncio
async def test_flow_only_and_missing_mac_are_observations_not_alerts(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id)
    await add_alerts(db,row,[{'event_type':'flow','flow':{'bytes_toserver':1000},
        'src_ip':'192.0.2.99','dest_ip':'198.51.100.99','ether':{}}])
    data=(await client.get('/api/investigation/observations')).json()
    unknown=next(item for item in data['observations'] if item['scope']['ip']=='192.0.2.99')
    assert unknown['scope']['mac'] is None and unknown['related_event_id'] is None
    assert unknown['observations']==1
    assert await db.pool.fetchval('SELECT count(*) FROM events')==1
    assert await db.pool.fetchval('SELECT count(*) FROM devices')==1


@pytest.mark.asyncio
async def test_history_is_not_limited_to_latest_50_events(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id)
    await add_alerts(db,row,[{'timestamp':(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()}]+
        [{'src_ip':f'192.0.2.{index}','ether':{}} for index in range(20,80)])
    first=(await client.get('/api/investigation/observations')).json()
    second=(await client.get('/api/investigation/observations?offset=50')).json()
    assert first['total']==second['total']==60
    assert len(first['observations'])==50 and len(second['observations'])==10
    assert not {str(e['scope']) for e in first['observations']} & {str(e['scope']) for e in second['observations']}
    assert '192.0.2.10' not in {e['scope']['ip'] for e in first['observations']+second['observations']}


@pytest.mark.asyncio
async def test_changed_mac_and_service_are_distinct_information(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id)
    await add_alerts(db,row,[{'timestamp':(datetime.now(timezone.utc)-timedelta(days=2)).isoformat()},
        {'ether':{'src_mac':'02:00:00:00:00:11'},'dest_port':8443}])
    addresses=(await client.get('/api/investigation/observations')).json()
    assert addresses['total']==1
    assert addresses['observations'][0]['scope']['mac']=='02:00:00:00:00:11'
    peers=(await client.get('/api/investigation/observations?kind=peers')).json()
    assert peers['total']==1 and peers['observations'][0]['scope']['dest_port']==8443


@pytest.mark.asyncio
async def test_future_observation_is_reported_and_excluded(db,review_case):
    client,_,event_id=review_case
    row=await template(db,event_id)
    await add_alerts(db,row,[{'timestamp':(datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
        'src_ip':'192.0.2.99','dest_ip':'198.51.100.99'}])
    data=(await client.get('/api/investigation/observations')).json()
    assert data['baseline']['future_records']==1
    assert '192.0.2.99' not in {item['scope']['ip'] for item in data['observations']}


@pytest.mark.asyncio
@pytest.mark.parametrize('params',[{'kind':'device'},{'hours':0},{'hours':169},{'offset':-1},{'limit':101}])
async def test_invalid_observation_query(review_case,params):
    client,_,_=review_case
    assert (await client.get('/api/investigation/observations',params=params)).status_code==422


@pytest.mark.asyncio
async def test_storage_failure_is_not_empty_observations(db,review_case):
    client,_,_=review_case
    await db.pool.execute('DROP TABLE eve_records')
    assert (await client.get('/api/investigation/observations')).status_code==503


@pytest.mark.asyncio
async def test_history_capacity_refuses_incomplete_first_seen(db,review_case):
    client,_,_=review_case
    await db.pool.execute("""INSERT INTO eve_records(ingest_id,sensor_id,source_id,event_type,observed_at,record)
        SELECT md5(index::text)::uuid,'capacity','capacity','flow',NOW(),
            '{"src_ip":"192.0.2.99","dest_ip":"198.51.100.99"}'::jsonb FROM generate_series(1,250000) index""")
    response=await client.get('/api/investigation/observations')
    assert response.status_code==413 and response.json()['detail']=='observation_history_capacity'


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',200),('analyst',200),('admin',200)])
async def test_observations_require_authenticated_viewer(review_case,monkeypatch,role,status):
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    client,_,_=review_case;secret=secrets.token_hex(32)
    client._transport.app.state.auth_manager=AuthManager(Config({'auth':{'enabled':True,'jwt_secret':secret,
        'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers={}
    if role:headers['Authorization']='Bearer '+jwt.encode({'sub':'viewer','role':role,
        'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
    assert (await client.get('/api/investigation/observations',headers=headers)).status_code==status
