"""실제 사건 목록의 담당자 필터와 기간 보고서의 집계·권한·CSV 계약."""
import csv
import io
from datetime import datetime, timedelta, timezone
import secrets

import bcrypt
import jwt
import pytest

from tests.test_web.test_business_reviews import review_case
from tests.test_web.test_case_workflows import change, case_path
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager


@pytest.mark.asyncio
async def test_owner_status_filters_include_unassigned_and_match_count(review_case):
    client, _, event_id = review_case
    initial = (await client.get('/api/events',params={'case_owner':'','case_status':'open'})).json()
    assert initial['total'] == 1 and initial['events'][0]['id'] == event_id
    assert initial['events'][0]['case_owner'] == ''
    assert (await client.put(case_path(review_case),json=change())).status_code == 200
    assigned = (await client.get('/api/events',params={'case_owner':'보안 담당자','case_status':'investigating'})).json()
    assert assigned['total'] == 1 and assigned['events'][0]['case_status'] == 'investigating'
    for params in ({'case_owner':''},{'case_status':'closed'},{'case_owner':"' OR TRUE --"}):
        data = (await client.get('/api/events',params=params)).json()
        assert data['total'] == 0 and data['events'] == []
    assert (await client.get('/api/events',params={'case_status':'invalid'})).status_code == 422


@pytest.mark.asyncio
async def test_report_preserves_severity_and_counts_stored_vs_occurrences(db, review_case):
    client, _, event_id = review_case
    assert (await client.put(case_path(review_case),json=change(status='closed'))).status_code == 200
    await db.pool.execute("UPDATE events SET metadata=metadata || $1::jsonb",{'aggregation':{'count':7}})
    response = await client.get('/api/reports/weekly')
    assert response.status_code == 200, response.text
    data = response.json()
    assert response.headers['cache-control'] == 'no-store'
    assert data['summary'] == {'stored_events':1,'known_occurrences':7,'unknown_occurrence_events':0,
        'occurrences_complete':True,'by_status':{'open':0,'investigating':0,'closed':1},'by_severity':{'CRITICAL':1}}
    assert data['events'][0]['note'] == change()['note']
    assert data['events'][0]['event_id'] == event_id
    assert data['period']['end_exclusive'] is True
    assert datetime.fromisoformat(data['period']['end'])-datetime.fromisoformat(data['period']['start']) == timedelta(days=7)


@pytest.mark.asyncio
@pytest.mark.parametrize('count',[None,True,-1,'7',1.5])
async def test_invalid_repetition_counts_are_reported_as_unknown(db, review_case, count):
    client, _, _ = review_case
    await db.pool.execute("UPDATE events SET metadata=metadata || $1::jsonb",{'aggregation':{'count':count}})
    data = (await client.get('/api/reports/weekly')).json()
    assert data['summary']['known_occurrences'] == 0
    assert data['summary']['unknown_occurrence_events'] == 1
    assert data['summary']['occurrences_complete'] is False
    assert data['events'][0]['occurrence_count'] is None


@pytest.mark.asyncio
async def test_report_start_inclusive_end_exclusive(db, review_case):
    client, _, event_id = review_case
    observed = datetime.fromisoformat(str(await db.pool.fetchval('SELECT timestamp FROM events WHERE id=$1',event_id)))
    included = await client.get('/api/reports/weekly',params={'start':observed.isoformat(),'end':(observed+timedelta(seconds=1)).isoformat()})
    excluded = await client.get('/api/reports/weekly',params={'start':(observed-timedelta(seconds=1)).isoformat(),'end':observed.isoformat()})
    assert included.json()['summary']['stored_events'] == 1
    assert excluded.json()['summary']['stored_events'] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('params',[{'start':'2026-10-01T00:00:00'},
    {'start':'2026-01-01T00:00:00Z','end':'2026-02-02T00:00:00Z'},
    {'start':'2026-01-02T00:00:00Z','end':'2026-01-01T00:00:00Z'}, {'format':'exe'}])
async def test_report_rejects_invalid_ranges(review_case,params):
    client, _, _ = review_case
    assert (await client.get('/api/reports/weekly',params=params)).status_code == 422


@pytest.mark.asyncio
async def test_csv_preserves_text_and_blocks_spreadsheet_formula_execution(db, review_case):
    client, _, _ = review_case
    owner = '=HYPERLINK("https://example.invalid")'
    note = '  @SUM(1,2)\n인계 메모'
    assert (await client.put(case_path(review_case),json=change(owner=owner,note=note))).status_code == 200
    await db.pool.execute('UPDATE events SET title=$1','+SUM(1,2)')
    response = await client.get('/api/reports/weekly?format=csv')
    assert response.status_code == 200
    row = list(csv.DictReader(io.StringIO(response.text)))[0]
    assert row['owner'] == "'"+owner
    assert row['note'] == "'"+note.strip()
    assert row['title'] == "'+SUM(1,2)"
    assert row['period_start'] and row['snapshot_at']
    exported = await client.get('/api/events/export?format=csv')
    row = list(csv.DictReader(io.StringIO(exported.text)))[0]
    assert row['case_owner'] == "'"+owner


@pytest.mark.asyncio
async def test_report_capacity_refuses_silent_truncation(db,review_case):
    client, _, _ = review_case
    await db.pool.execute("""INSERT INTO events(engine,severity,title,timestamp)
        SELECT 'test','INFO','capacity event',NOW() FROM generate_series(1,10000)""")
    response = await client.get('/api/reports/weekly')
    assert response.status_code == 413 and response.json()['detail'] == 'report_capacity'


@pytest.mark.asyncio
@pytest.mark.parametrize('role,status',[(None,401),('viewer',200),('analyst',200),('admin',200)])
async def test_report_requires_authenticated_viewer(review_case,monkeypatch,role,status):
    monkeypatch.delenv('NETWATCHER_JWT_SECRET',raising=False)
    client, _, _ = review_case
    secret = secrets.token_hex(32)
    client._transport.app.state.auth_manager = AuthManager(Config({'auth':{'enabled':True,
        'jwt_secret':secret,'password':bcrypt.hashpw(b'test',bcrypt.gensalt(rounds=4)).decode()}}))
    headers = {}
    if role:
        token = jwt.encode({'sub':'report-viewer','role':role,'exp':datetime.now(timezone.utc)+timedelta(minutes=5)},secret,algorithm='HS256')
        headers['Authorization']='Bearer '+token
    assert (await client.get('/api/reports/weekly',headers=headers)).status_code == status


@pytest.mark.asyncio
async def test_event_exports_follow_owner_status_and_search_filters(review_case):
    client, _, _ = review_case
    assert (await client.put(case_path(review_case),json=change())).status_code == 200
    for params in ({'case_owner':''},{'case_owner':'다른 담당자'},{'case_status':'closed'},{'q':'no matching title'}):
        result = await client.get('/api/events/export',params=params)
        assert result.status_code == 200
        assert result.json()['events'] == []
    result = await client.get('/api/events/export',params={'case_owner':'보안 담당자','case_status':'investigating'})
    assert result.json()['total'] == 1


@pytest.mark.asyncio
async def test_empty_csv_has_headers_and_report_storage_failure_is_unavailable(db,review_case):
    client, _, _ = review_case
    result = await client.get('/api/reports/weekly',params={'format':'csv',
        'start':'2020-01-01T00:00:00Z','end':'2020-01-02T00:00:00Z'})
    assert result.status_code == 200
    reader = csv.DictReader(io.StringIO(result.text))
    assert 'occurrence_count' in reader.fieldnames and list(reader) == []
    await db.pool.execute('DROP TABLE case_history')
    assert (await client.get('/api/reports/weekly')).status_code == 503
