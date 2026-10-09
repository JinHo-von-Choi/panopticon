"""감사 보관 후 용량 회수·미확정 결과·중복 실행 방지를 실제 DB로 확인한다."""

from uuid import UUID, uuid4

import pytest

from netwatcher.services.sensor_control import SensorControlError
from netwatcher.web.audit_log import AuditLogger
from tests.test_services.test_sensor_control import control


@pytest.mark.asyncio
async def test_capacity_reclaims_completed_claims_and_never_replays_archived_id(db, control, monkeypatch):
    import netwatcher.services.sensor_control as module
    monkeypatch.setattr(module,'MAX_CLAIMS',2)
    service,registry,editor,request,send,*_=control
    original=None
    for threshold in (7,8,9):
        state=await send(request())
        change=request('engine.configure',base=state['base_version'],updates={'threshold':threshold})
        original=original or change
        assert (await send(change))['status']=='applied'
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims')==1
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_archived'")==2
    history=await AuditLogger(db.pool).change_history(original.request_id)
    assert [row['action'] for row in history]==['sensor_change_prepared','sensor_change_applied','sensor_change_archived']
    assert history[-1]['details']['outcome']=='applied'
    assert history[-1]['user']=='sensor-maintenance'
    assert history[-1]['details']['actor_id']==original.actor_id
    state=await send(request())
    replay=request('engine.configure',request_id=original.request_id,base=state['base_version'],updates={'threshold':40})
    with pytest.raises(SensorControlError) as refused:
        await send(replay)
    assert refused.value.code=='sensor_request_expired'
    assert (await send(request()))['engine']['config']['threshold']==9
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims')==1


@pytest.mark.asyncio
async def test_prepared_claims_only_archive_after_owner_loss_and_keep_unknown(db, control):
    service,registry,editor,request,send,*_=control
    actor=UUID(request().actor_id);orphan=uuid4();current=uuid4();young=uuid4()
    for rid,owner,age in ((orphan,uuid4(),'10 minutes'),(current,service.owner,'10 minutes'),(young,uuid4(),'1 minute')):
        await db.pool.execute('''INSERT INTO sensor_control_claims(request_id,sensor_id,owner,actor_id,command_hash,prepared_at)
            VALUES($1,'office',$2,$3,$4,clock_timestamp()-$5::text::interval)''',rid,owner,actor,'a'*64,age)
    state=await send(request())
    assert (await send(request('engine.configure',base=state['base_version'],updates={'threshold':7})))['status']=='applied'
    assert not await db.pool.fetchval('SELECT EXISTS(SELECT 1 FROM sensor_control_claims WHERE request_id=$1)',orphan)
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims WHERE request_id=ANY($1::uuid[])',[current,young])==2
    history=await AuditLogger(db.pool).change_history(str(orphan))
    assert history[-1]['details']['outcome']=='unknown'
    state=await send(request())
    with pytest.raises(SensorControlError) as refused:
        await send(request('engine.configure',request_id=str(orphan),base=state['base_version'],updates={'threshold':8}))
    assert refused.value.code=='sensor_request_expired'
    assert (await send(request()))['engine']['config']['threshold']==7


@pytest.mark.asyncio
async def test_archive_failure_keeps_original_claim_and_prevents_new_mutation(db, control, monkeypatch):
    import netwatcher.services.sensor_control as module
    monkeypatch.setattr(module,'MAX_CLAIMS',1)
    service,registry,editor,request,send,*_=control
    state=await send(request())
    old=request('engine.configure',base=state['base_version'],updates={'threshold':7})
    await send(old)
    await db.pool.execute("""CREATE FUNCTION reject_claim_archive() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action='sensor_change_archived' THEN RAISE EXCEPTION 'injected archive failure'; END IF; RETURN NEW; END $$""")
    await db.pool.execute('CREATE TRIGGER reject_claim_archive BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_claim_archive()')
    state=await send(request())
    with pytest.raises(SensorControlError):
        await send(request('engine.configure',base=state['base_version'],updates={'threshold':8}))
    assert (await send(request()))['engine']['config']['threshold']==7
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims')==1
    assert await db.pool.fetchval('SELECT status FROM sensor_control_claims')=='completed'
    assert not await db.pool.fetchval("SELECT EXISTS(SELECT 1 FROM audit_log WHERE action='sensor_change_archived')")


@pytest.mark.asyncio
async def test_full_ten_thousand_claims_reclaim_only_bounded_batch(db, control):
    service,registry,editor,request,send,*_=control
    await db.pool.execute('''INSERT INTO sensor_control_claims
        (request_id,sensor_id,owner,actor_id,command_hash,status,result,prepared_at,completed_at)
        SELECT md5('claim-retention-'||n)::uuid,'office',$1,$2,repeat('a',64),'completed',
            '{"status":"applied"}'::jsonb,clock_timestamp()-INTERVAL '1 hour',clock_timestamp()
        FROM generate_series(1,10000) AS n''',service.owner,UUID(request().actor_id))
    state=await send(request())
    assert (await send(request('engine.configure',base=state['base_version'],updates={'threshold':7})))['status']=='applied'
    assert await db.pool.fetchval('SELECT count(*) FROM sensor_control_claims')==9751
    assert await db.pool.fetchval("SELECT count(*) FROM audit_log WHERE action='sensor_change_archived'")==250


@pytest.mark.asyncio
async def test_locked_completed_claim_is_not_deleted_or_waited_on(db, control, monkeypatch):
    import asyncio
    import netwatcher.services.sensor_control as module
    monkeypatch.setattr(module,'MAX_CLAIMS',1)
    service,registry,editor,request,send,*_=control
    state=await send(request())
    original=request('engine.configure',base=state['base_version'],updates={'threshold':7})
    await send(original)
    state=await send(request())
    async with db.pool.acquire() as blocker, blocker.transaction():
        await blocker.fetchrow('SELECT request_id FROM sensor_control_claims WHERE request_id=$1 FOR UPDATE',UUID(original.request_id))
        async with asyncio.timeout(2):
            with pytest.raises(SensorControlError) as refused:
                await send(request('engine.configure',base=state['base_version'],updates={'threshold':8}))
        assert refused.value.code=='sensor_control_capacity'
        assert not await db.pool.fetchval("SELECT EXISTS(SELECT 1 FROM audit_log WHERE action='sensor_change_archived')")
    assert (await send(request()))['engine']['config']['threshold']==7
    assert (await send(request('engine.configure',base=state['base_version'],updates={'threshold':8})))['status']=='applied'
