"""감사 보관된 요청의 HTTP 재실행 거절과 원래 적용·미확정 결과 조회."""

from uuid import uuid4

import pytest

from tests.test_web.test_remote_engines import engine_api
from tests.test_services.test_sensor_control import control


@pytest.mark.asyncio
async def test_http_archived_id_is_not_reused_and_applied_outcome_survives_failed_retry(db,engine_api,monkeypatch):
    import netwatcher.services.sensor_control as module
    monkeypatch.setattr(module,'MAX_CLAIMS',1)
    client,headers,*_=engine_api
    original=str(uuid4())
    for request_id,threshold in ((original,7),(str(uuid4()),8)):
        state=await client.get('/api/engines/port_scan',headers=headers)
        changed=await client.put('/api/engines/port_scan/config',headers=headers,json={
            'request_id':request_id,'base_version':state.json()['base_version'],'config':{'threshold':threshold}})
        assert changed.status_code==200
    state=await client.get('/api/engines/port_scan',headers=headers)
    retry=await client.put('/api/engines/port_scan/config',headers=headers,json={
        'request_id':original,'base_version':state.json()['base_version'],'config':{'threshold':40}})
    assert retry.status_code==409 and retry.json()['detail']['code']=='sensor_request_expired'
    history=await client.get('/api/audit/changes/'+original,headers=headers)
    assert history.status_code==200 and history.json()['outcome']=='applied'
    assert history.json()['requires_reconciliation'] is False
    assert 'sensor_change_archived' in {entry['action'] for entry in history.json()['entries']}
    current=await client.get('/api/engines/port_scan',headers=headers)
    assert current.json()['engine']['config']['threshold']==8


@pytest.mark.asyncio
async def test_archive_unknown_is_not_overridden_by_later_failed_http_record(db,engine_api):
    client,headers,*_=engine_api
    request_id=str(uuid4())
    await db.pool.execute("""INSERT INTO audit_log(user_id,action,resource,details) VALUES
        ('sensor-maintenance','sensor_change_archived','sensor/office/claims',$1),
        ('test','api_mutation','/api/engines/port_scan/config',$2)""",
        {'request_id':request_id,'outcome':'unknown'},{'request_id':request_id,'outcome':'failed'})
    for _ in range(30):
        await db.pool.execute("INSERT INTO audit_log(user_id,action,resource,details) VALUES('test','api_mutation','/api/engines/port_scan/config',$1)",{'request_id':request_id,'outcome':'failed'})
    history=await client.get('/api/audit/changes/'+request_id,headers=headers)
    assert history.status_code==200 and history.json()['outcome']=='unknown'
    assert len(history.json()['entries'])<=20
    assert history.json()['requires_reconciliation'] is True
