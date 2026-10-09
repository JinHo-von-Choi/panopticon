"""반복 경보는 원본과 개별 판정을 유지하고 식별 범위를 넘지 않는다."""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from netwatcher.ingest.eve import decode_eve_line
from netwatcher.ingest.repository import EveRepository
from tests.test_web.test_business_reviews import review_case, decision


async def add_alerts(db, template, changes):
    repository = EveRepository(db)
    records = []
    generation = str(uuid.uuid4())
    for offset, change in enumerate(changes):
        row = dict(template) | change
        raw = (json.dumps(row)+'\n').encode()
        records.append(decode_eve_line(raw, sensor_id='test', source_id='office',
                                      generation=generation, offset=offset))
    revision, _ = await repository.load('test', 'office')
    await repository.commit('test', 'office', revision, {}, records)


async def template(db, event_id):
    row = await db.pool.fetchrow('SELECT record FROM eve_records WHERE event_id=$1', event_id)
    record = row['record']
    return {'event_type':'alert', 'timestamp':record['observed_at'], 'src_ip':record['src_ip'],
            'dest_ip':record['dest_ip'], 'src_port':40000, 'dest_port':443, 'proto':'TCP',
            'ether':{'src_mac':record['src_mac']}, 'alert':{'signature_id':100, 'severity':1}}


@pytest.mark.asyncio
async def test_new_repetition_does_not_inherit_existing_normal_review(db, review_case):
    client, path, event_id = review_case
    assert (await client.put(path, json=decision())).status_code == 200
    await add_alerts(db, await template(db,event_id), [{'flow_id':999, 'src_port':45000}])
    response = await client.get(f'/api/events/{event_id}/group')
    assert response.status_code == 200, response.text
    group = response.json()
    assert group['total'] == 2 and group['without_review'] == 1 and group['not_closed'] == 2
    assert group['window']['end_exclusive'] is True
    assert response.headers['cache-control'] == 'no-store'
    assert sum(row['recorded_decision'] is None for row in group['events']) == 1
    new_id = next(row['id'] for row in group['events'] if row['id'] != event_id)
    assert (await client.get(f'/api/events/{new_id}/business-review')).json()['state'] != 'normal_confirmed'
    assert (await client.get(path)).json()['state'] == 'normal_confirmed'
    assert await db.pool.fetchval('SELECT count(*) FROM events') == 2
    assert await db.pool.fetchval("SELECT count(*) FROM events WHERE severity='CRITICAL'") == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('change',[
    {'src_ip':'192.0.2.12'}, {'dest_ip':'198.51.100.22'}, {'dest_port':8443}, {'proto':'UDP'},
    {'ether':{'src_mac':'02:00:00:00:00:11'}},
    {'ether':{'src_macs':['02:00:00:00:00:10','02:00:00:00:00:11']}},
    {'alert':{'signature_id':101,'severity':1}},
    {'alert':{'signature_id':100,'severity':2}},
    {'alert':{'signature_id':100,'severity':1,'rev':2}},
])
async def test_different_identity_rule_or_service_is_not_grouped(db, review_case, change):
    client, _, event_id = review_case
    await add_alerts(db, await template(db,event_id), [change])
    assert (await client.get(f'/api/events/{event_id}/group')).json()['total'] == 1


@pytest.mark.asyncio
async def test_hour_window_pagination_and_report_dont_double_count(db, review_case):
    client, _, event_id = review_case
    row = await template(db,event_id)
    observed = datetime.fromisoformat(row['timestamp'])
    boundary = observed.replace(minute=0,second=0,microsecond=0)+timedelta(hours=1)
    await add_alerts(db,row,[{} for _ in range(55)]+[{'timestamp':boundary.isoformat()}])
    page1 = (await client.get(f'/api/events/{event_id}/group')).json()
    page2 = (await client.get(f'/api/events/{event_id}/group?offset=50')).json()
    assert page1['total'] == page2['total'] == 56
    assert len(page1['events']) == 50 and len(page2['events']) == 6
    assert not {e['id'] for e in page1['events']} & {e['id'] for e in page2['events']}
    report = (await client.get('/api/reports/weekly', params={
        'end':(boundary+timedelta(hours=1)).isoformat()})).json()
    assert report['summary']['stored_events'] == report['summary']['known_occurrences'] == 57


@pytest.mark.asyncio
async def test_missing_addresses_cannot_merge_unidentified_devices(db, review_case):
    client, _, event_id = review_case
    row = await template(db,event_id)
    row.pop('src_ip')
    await add_alerts(db,row,[{},{}])
    ids = await db.pool.fetch("SELECT event_id FROM eve_records WHERE record->>'src_ip' IS NULL")
    data = (await client.get(f"/api/events/{ids[0]['event_id']}/group")).json()
    assert data['addresses_complete'] is False and data['total'] == 1


@pytest.mark.asyncio
async def test_missing_native_and_invalid_queries(db, review_case):
    client, _, event_id = review_case
    assert (await client.get('/api/events/9223372036854775807/group')).status_code == 404
    for query in ('offset=-1','limit=101','limit=0'):
        assert (await client.get(f'/api/events/{event_id}/group?{query}')).status_code == 422
    await db.pool.execute('DELETE FROM eve_records WHERE event_id=$1',event_id)
    assert (await client.get(f'/api/events/{event_id}/group')).json()['available'] is False


@pytest.mark.asyncio
async def test_group_filters_sensor_source_and_survives_member_retention(db, review_case):
    client, _, event_id = review_case
    row = await template(db,event_id)
    repository = EveRepository(db)
    for sensor, source in [('other','office'),('test','other')]:
        decoded = decode_eve_line(json.dumps(row).encode(), sensor_id=sensor, source_id=source,
                                 generation=str(uuid.uuid4()), offset=0)
        await repository.commit(sensor,source,None,{},[decoded])
    await add_alerts(db,row,[{}])
    assert (await client.get(f'/api/events/{event_id}/group')).json()['total'] == 2
    await db.pool.execute("UPDATE eve_records SET received_at=NOW()-interval '40 days' WHERE event_id=$1",event_id)
    assert await repository.prune('test','office') == 1
    member = await db.pool.fetchval("SELECT event_id FROM eve_records WHERE sensor_id='test' AND source_id='office' AND event_type='alert'")
    assert (await client.get(f'/api/events/{member}/group')).json()['total'] == 1
    assert (await client.get(f'/api/events/{event_id}/group')).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',200),('analyst',200),('admin',200)])
@pytest.mark.parametrize('overview',[False,True])
async def test_group_requires_authenticated_viewer(review_case, monkeypatch, role, status, overview):
    import bcrypt
    import jwt
    import secrets
    from netwatcher.utils.config import Config
    from netwatcher.web.auth import AuthManager
    monkeypatch.delenv('NETWATCHER_JWT_SECRET', raising=False)
    client, _, event_id = review_case
    secret = secrets.token_hex(32)
    client._transport.app.state.auth_manager = AuthManager(Config({'auth':{'enabled':True,
        'jwt_secret':secret,'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers = {}
    if role:
        headers['Authorization'] = 'Bearer '+jwt.encode({'sub':'viewer','role':role,
            'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
    assert (await client.get('/api/events/groups' if overview else f'/api/events/{event_id}/group',headers=headers)).status_code == status


@pytest.mark.asyncio
async def test_group_storage_failure_is_unavailable(db, review_case):
    client, _, event_id = review_case
    await db.pool.execute('DROP TABLE case_history; DROP TABLE case_workflows')
    assert (await client.get(f'/api/events/{event_id}/group')).status_code == 503


@pytest.mark.asyncio
async def test_member_closure_only_changes_that_member(db, review_case):
    from tests.test_web.test_case_workflows import change, case_path
    client, _, event_id = review_case
    await add_alerts(db,await template(db,event_id),[{}])
    assert (await client.put(case_path(review_case),json=change(status='closed'))).status_code == 200
    data = (await client.get(f'/api/events/{event_id}/group')).json()
    assert data['total'] == 2 and data['not_closed'] == 1
    assert sum(row['status']=='closed' for row in data['events']) == 1


@pytest.mark.asyncio
async def test_group_overview_counts_repetitions_and_preserves_individual_reviews(db, review_case):
    client, path, event_id = review_case
    await client.put(path,json=decision())
    await add_alerts(db,await template(db,event_id),[{}, {}, {'dest_port':8443}])
    response = await client.get('/api/events/groups')
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['total'] == 2 and data['stored_alerts'] == 4
    group = next(g for g in data['groups'] if g['occurrences']==3)
    assert group['without_review'] == 2 and group['not_closed'] == 3
    assert group['scope']['dest_port'] == 443
    detail = (await client.get(f"/api/events/{group['representative_id']}/group")).json()
    assert detail['total'] == group['occurrences']
    assert response.headers['cache-control']=='no-store'


@pytest.mark.asyncio
async def test_overview_time_boundaries_and_offsets(db, review_case):
    client, _, event_id = review_case
    row = await template(db,event_id)
    observed = datetime.fromisoformat(row['timestamp'])
    boundary = observed.replace(minute=0,second=0,microsecond=0)+timedelta(hours=1)
    await add_alerts(db,row,[{'timestamp':boundary.isoformat()}, {'dest_port':8443}])
    params={'start':observed.isoformat(),'end':(boundary+timedelta(seconds=1)).isoformat(),'limit':1}
    first=(await client.get('/api/events/groups',params=params)).json()
    second=(await client.get('/api/events/groups',params=params|{'offset':1})).json()
    beyond=(await client.get('/api/events/groups',params=params|{'offset':100})).json()
    assert first['total']==second['total']==beyond['total']==3
    assert first['groups'][0]['representative_id']!=second['groups'][0]['representative_id']
    assert beyond['groups']==[]
    exclusive=(await client.get('/api/events/groups',params={'start':observed.isoformat(),'end':boundary.isoformat()})).json()
    assert exclusive['total']==exclusive['stored_alerts']==2


@pytest.mark.asyncio
@pytest.mark.parametrize('params',[{'start':'2026-10-01T00:00:00'},
    {'start':'2026-10-01T00:00:00Z','end':'2026-10-09T00:00:00Z'}, {'limit':101}, {'offset':-1}])
async def test_overview_rejects_invalid_ranges(review_case,params):
    client, _, _ = review_case
    assert (await client.get('/api/events/groups',params=params)).status_code==422


@pytest.mark.asyncio
async def test_overview_empty_period_and_partial_hour(db, review_case):
    client, _, event_id = review_case
    row = await template(db,event_id)
    observed = datetime.fromisoformat(row['timestamp'])
    await add_alerts(db,row,[{'timestamp':(observed+timedelta(seconds=1)).isoformat()}])
    data=(await client.get('/api/events/groups',params={'start':(observed+timedelta(seconds=1)).isoformat(),
        'end':(observed+timedelta(seconds=2)).isoformat()})).json()
    assert data['stored_alerts']==1 and data['groups'][0]['occurrences']==1
    empty=(await client.get('/api/events/groups',params={'start':'2020-01-01T00:00:00Z','end':'2020-01-02T00:00:00Z'})).json()
    assert empty['total']==0 and empty['stored_alerts']==0 and empty['groups']==[]


@pytest.mark.asyncio
async def test_overview_refuses_partial_success_over_capacity(db,review_case):
    client, _, event_id = review_case
    await db.pool.execute("""WITH added AS (
        INSERT INTO events(engine,severity,title,timestamp)
        SELECT 'capacity','WARNING','Capacity alert',NOW() FROM generate_series(1,50000)
        RETURNING id
    ) INSERT INTO eve_records(ingest_id,sensor_id,source_id,event_type,observed_at,record,event_id)
        SELECT md5(id::text)::uuid,'capacity','capacity','alert',NOW(),
            '{"src_ip":"192.0.2.10","dest_ip":"198.51.100.20","details":{"signature_id":100,"severity":2}}'::jsonb,id FROM added""")
    response=await client.get('/api/events/groups')
    assert response.status_code==413 and response.json()['detail']=='group_period_capacity'
    assert await db.pool.fetchval('SELECT count(*) FROM events')==50001
