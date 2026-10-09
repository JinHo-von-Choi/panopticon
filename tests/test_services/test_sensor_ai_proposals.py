"""센서 내부 AI 제안은 출처·설정 스냅샷을 보존하고 운영 설정을 쓰지 않는다."""

from pathlib import Path
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from netwatcher.detection.proposals import ProposalService, ProposalError
from netwatcher.services.ai_analyzer import AIAnalyzerService
from netwatcher.storage.repositories import ConfigProposalRepository, EventRepository
from tests.test_web.test_remote_proposals import proposals_api, engine_api, control, validate


def bound_analyzer(db, config, api):
    client, header, control_service, registry, editor, accounts, server, stopped, replay = api
    config.raw['ai_analyzer'] = {'enabled': True, 'apply_mode':'propose', 'consecutive_fp_threshold':1,
                                 'consecutive_mt_threshold':1}
    proposals = ProposalService(registry, editor, ConfigProposalRepository(db))
    proposals.bind_sensor_origin(control_service)
    analyzer = AIAnalyzerService(config, EventRepository(db), registry, AsyncMock(), editor,
                                 proposal_service=proposals)
    return analyzer, proposals


@pytest.mark.asyncio
async def test_real_ai_queue_origin_integer_cap_and_human_approval(db, config, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    analyzer, _ = bound_analyzer(db, config, proposals_api)
    original = Path(editor._path).read_bytes()
    active = registry._find_active('port_scan')
    analyzer._try_adjust_threshold('port_scan', {'threshold':10.0})
    await analyzer.stop()
    assert not analyzer._proposal_tasks
    row = await db.pool.fetchrow('SELECT * FROM config_proposals')
    assert row['source']=='ai' and row['sensor_id']=='office' and row['sensor_owner']==service.owner
    assert row['params']=={'threshold':6} and type(row['params']['threshold']) is int
    assert row['before']['threshold']==5 and row['status']=='pending' and row['applied'] is None
    assert Path(editor._path).read_bytes()==original and registry._find_active('port_scan') is active
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_ai_proposal_prepared'")==1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_ai_proposal_saved'")==1
    pid=row['id']
    state=(await client.get(f'/api/proposals/{pid}',headers=header)).json()
    state,_=await validate(proposals_api,state)
    response=await client.post(f'/api/proposals/{pid}/approve',headers=header,
        json={'request_id':str(uuid4()),'base_version':state['base_version']})
    assert response.status_code==200,response.text
    assert editor.get_engine_config('port_scan')['threshold']==6
    assert registry._find_active('port_scan')._threshold==6 and not stopped


@pytest.mark.asyncio
async def test_ai_snapshot_drift_rejects_without_retargeting_new_settings(db, config, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    analyzer, proposals=bound_analyzer(db,config,proposals_api)
    before=analyzer._read_current_config('port_scan')
    editor.update_engine_config('port_scan',{'threshold':7})
    changed=Path(editor._path).read_bytes()
    with pytest.raises(ProposalError,match='분석 이후 설정'):
        await proposals.submit('port_scan',{'threshold':6},source='ai',expected_config=before)
    assert await db.pool.fetchval('SELECT count(*) FROM config_proposals')==0
    assert Path(editor._path).read_bytes()==changed
    assert registry._find_active('port_scan')._threshold==5 and not stopped
    await analyzer.stop()


@pytest.mark.asyncio
async def test_ai_origin_requires_snapshot_and_valid_active_lease(db, config, proposals_api):
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    analyzer, proposals=bound_analyzer(db,config,proposals_api)
    with pytest.raises(ProposalError):
        await proposals.submit('port_scan',{'threshold':6},source='ai')
    with pytest.raises(ProposalError):
        await proposals.submit('port_scan',{'threshold':6},source='human',expected_config=editor.get_engine_config('port_scan'))
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
    with pytest.raises(ProposalError,match='소유권'):
        await proposals.submit('port_scan',{'threshold':6},source='ai',expected_config=editor.get_engine_config('port_scan'))
    assert await db.pool.fetchval('SELECT count(*) FROM config_proposals')==0
    assert registry._find_active('port_scan')._threshold==5 and not stopped
    await analyzer.stop()


@pytest.mark.asyncio
async def test_ai_saved_audit_failure_rolls_back_proposal_and_prepared_audit(db, config, proposals_api):
    import asyncpg
    client, header, service, registry, editor, accounts, server, stopped, replay = proposals_api
    analyzer, proposals=bound_analyzer(db,config,proposals_api)
    await db.pool.execute("""CREATE FUNCTION reject_ai_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='sensor_ai_proposal_saved' THEN RAISE EXCEPTION 'owned audit fault'; END IF;
        RETURN NEW; END; $$;
        CREATE TRIGGER reject_ai_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_ai_audit();""")
    with pytest.raises(asyncpg.RaiseError):
        await proposals.submit('port_scan',{'threshold':6},source='ai',expected_config=editor.get_engine_config('port_scan'))
    assert await db.pool.fetchval('SELECT count(*) FROM config_proposals')==0
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_ai_proposal_prepared'")==0
    assert registry._find_active('port_scan')._threshold==5 and not stopped
    await analyzer.stop()


@pytest.mark.asyncio
async def test_integer_decrease_stays_within_percentage_limit(db, config, proposals_api):
    analyzer,_=bound_analyzer(db,config,proposals_api)
    captured=[]
    analyzer._record_proposal=lambda *values:captured.append(values)
    analyzer._try_lower_threshold('port_scan',{'threshold':1.0})
    assert captured[0][1]=={'threshold':5}
    assert captured[0][4]['threshold']==5
    await analyzer.stop()
