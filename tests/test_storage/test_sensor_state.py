"""분리 센서의 실제 DB 실행 소유권과 관측 상태 전달 계약."""

import asyncio
import json
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest
import httpx

from netwatcher.storage.sensor_state import SensorStateRepository, SensorLeaseLost, StoredSensorObservation


@pytest.mark.asyncio
async def test_concurrent_claim_allows_one_sensor_process(db):
    repo = SensorStateRepository(db)
    owners = [uuid4(), uuid4(), uuid4()]
    results = await asyncio.gather(*(repo.claim("mirror-a", owner) for owner in owners), return_exceptions=True)
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, SensorLeaseLost) for result in results) == 2
    assert await db.pool.fetchval("SELECT count(*) FROM sensor_runtime_state") == 1


@pytest.mark.asyncio
async def test_new_owner_rejects_previous_process_heartbeat_and_shutdown(db):
    repo = SensorStateRepository(db)
    previous, current = uuid4(), uuid4()
    await repo.claim("mirror-a", previous)
    await repo.publish("mirror-a", previous, {"state": "partial", "no_traffic_observed": False})
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
    assert (await repo.read("mirror-a"))["stale"] is True
    await repo.claim("mirror-a", current)
    with pytest.raises(SensorLeaseLost):
        await repo.publish("mirror-a", previous, {"state": "observed"})
    assert await repo.release("mirror-a", previous) is False
    await repo.publish("mirror-a", current, {"state": "partial"})
    assert (await repo.read("mirror-a"))["stale"] is False
    assert await repo.release("mirror-a", current) is True
    assert (await repo.read("mirror-a"))["stale"] is True


@pytest.mark.asyncio
async def test_expired_owner_cannot_extend_lease_without_claiming_again(db):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
    with pytest.raises(SensorLeaseLost):
        await repo.publish("mirror-a", owner, {"state": "observed"})


@pytest.mark.asyncio
async def test_db_clock_not_sensor_wall_clock_controls_freshness(db):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await repo.publish("mirror-a", owner, {"state": "partial", "last_heartbeat_at": -100000})
    row = await repo.read("mirror-a")
    assert row["stale"] is False and row["heartbeat_age_seconds"] < 5


@pytest.mark.asyncio
async def test_empty_failed_stale_and_mutated_cache_do_not_claim_healthy_observation(db, monkeypatch):
    repo = SensorStateRepository(db)
    view = StoredSensorObservation(repo, "mirror-a")
    assert view.snapshot()["state"] == "unknown"
    assert view.snapshot()["no_traffic_observed"] is None
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await view.refresh()
    assert view.snapshot()["state"] == "unknown"
    await repo.publish("mirror-a", owner, {"state": "partial", "reasons": ["SPAN 범위 확인 필요"], "no_traffic_observed": False})
    await view.refresh()
    output = view.snapshot()
    output["reasons"].clear()
    assert view.snapshot()["reasons"] == ["SPAN 범위 확인 필요"]
    view._read_at = time.monotonic() - 11
    assert view.snapshot()["state"] == "stale"
    assert view.snapshot()["no_traffic_observed"] is None
    await view.refresh()
    async def unavailable(_):
        raise OSError("Injected DB failure")
    monkeypatch.setattr(repo, "read", unavailable)
    with pytest.raises(OSError):
        await view.refresh()
    assert view.snapshot()["state"] == "stale"
    assert view.snapshot()["sensor_heartbeat"]["confirmed"] is False


@pytest.mark.asyncio
async def test_cache_cannot_extend_database_lease(db):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await repo.publish("mirror-a", owner, {"state": "partial", "no_traffic_observed": False})
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()+INTERVAL '500 milliseconds'")
    view = StoredSensorObservation(repo, "mirror-a")
    await view.refresh()
    assert view.snapshot()["sensor_heartbeat"]["confirmed"] is True
    view._read_at -= 1
    assert view.snapshot()["state"] == "stale"
    assert view.snapshot()["sensor_heartbeat"]["confirmed"] is False
    assert view.snapshot()["no_traffic_observed"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("termination", ["cancel", "timeout"])
async def test_interrupted_refresh_invalidates_previous_confirmed_cache(db, monkeypatch, termination):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await repo.publish("mirror-a", owner, {"state": "observed", "no_traffic_observed": False})
    view = StoredSensorObservation(repo, "mirror-a")
    await view.refresh()
    assert view.snapshot()["sensor_heartbeat"]["confirmed"] is True
    entered, blocked = asyncio.Event(), asyncio.Event()
    original = repo.read
    async def delayed(sensor_id):
        row = await original(sensor_id)
        entered.set()
        await blocked.wait()
        return row
    monkeypatch.setattr(repo, "read", delayed)
    async def refresh():
        if termination == "timeout":
            async with asyncio.timeout(.2):
                await view.refresh()
        else:
            await view.refresh()
    task = asyncio.create_task(refresh())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        if termination == "cancel":
            task.cancel()
        with pytest.raises(asyncio.CancelledError if termination == "cancel" else TimeoutError):
            await task
        stale = view.snapshot()
        assert stale["state"] == "stale"
        assert stale["sensor_heartbeat"]["confirmed"] is False
        assert stale["no_traffic_observed"] is None
        monkeypatch.setattr(repo, "read", original)
        await view.refresh()
        assert view.snapshot()["state"] == "observed"
        assert view.snapshot()["sensor_heartbeat"]["confirmed"] is True
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_refreshes_are_serialized_and_canceled_waiter_does_not_invalidate_success(db, monkeypatch):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await repo.publish("mirror-a", owner, {"state": "partial"})
    view = StoredSensorObservation(repo, "mirror-a")
    entered, release = asyncio.Event(), asyncio.Event()
    original = repo.read
    calls = []
    async def delayed(sensor_id):
        calls.append(sensor_id)
        row = await original(sensor_id)
        entered.set()
        await release.wait()
        return row
    monkeypatch.setattr(repo, "read", delayed)
    first = asyncio.create_task(view.refresh())
    second = None
    try:
        await asyncio.wait_for(entered.wait(), 2)
        second = asyncio.create_task(view.refresh())
        await asyncio.sleep(0)
        assert calls == ["mirror-a"]
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        release.set()
        await first
        assert view.snapshot()["state"] == "partial"
        assert view.snapshot()["sensor_heartbeat"]["confirmed"] is True
    finally:
        release.set()
        tasks = [task for task in (first, second) if task is not None]
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_snapshot_limits_and_registration_bound_are_enforced(db, monkeypatch):
    import netwatcher.storage.sensor_state as module
    monkeypatch.setattr(module, "MAX_SENSORS", 1)
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    with pytest.raises(ValueError):
        await repo.claim("mirror-b", uuid4())
    for snapshot in ([], {"value": float("nan")}, {"value": "x" * 60000}):
        with pytest.raises(ValueError):
            await repo.publish("mirror-a", owner, snapshot)
    assert (await repo.read("mirror-a"))["snapshot"] == {}
    for lease in (True, 1, 121, float("nan")):
        with pytest.raises(ValueError):
            await repo.publish("mirror-a", owner, {}, lease_seconds=lease)


@pytest.mark.asyncio
async def test_stored_snapshot_works_with_existing_console_observation_api(db, config):
    from netwatcher.alerts.stream import EventStream
    from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository
    from netwatcher.web.server import create_app
    view = StoredSensorObservation(SensorStateRepository(db), "mirror-a")
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db),
                     EventStream(), observation_service=view)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        unknown = await client.get("/api/observation")
        assert unknown.status_code == 200, unknown.text
        assert unknown.json()["state"] == "unknown"
        assert unknown.json()["no_traffic_observed"] is None
        assert unknown.json()["reasons"]
        owner = uuid4()
        await view.repository.claim("mirror-a", owner)
        await view.repository.publish("mirror-a", owner, {"state": "partial", "reasons": ["SPAN 범위 미확인"], "no_traffic_observed": False})
        await view.refresh()
        observed = (await client.get("/api/observation")).json()
        assert observed["state"] == "partial" and observed["execution_process"] == "separate"
        await view.repository.release("mirror-a", owner)
        await view.refresh()
        stale = (await client.get("/api/observation")).json()
        assert stale["state"] == "stale" and stale["no_traffic_observed"] is None


@pytest.mark.asyncio
async def test_actual_separate_python_process_reads_persisted_sensor_state(db, config):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    await repo.publish("mirror-a", owner, {"state": "partial", "no_traffic_observed": False})
    Path(config.config_path).chmod(0o600)
    code = """
import asyncio,json,sys
sys.path.insert(0,sys.argv[2])
from netwatcher.utils.config import Config
from netwatcher.storage.database import Database
from netwatcher.storage.sensor_state import SensorStateRepository,StoredSensorObservation
async def main():
 db=Database(Config.load(sys.argv[1]))
 await db.connect()
 try:
  view=StoredSensorObservation(SensorStateRepository(db),'mirror-a')
  await view.refresh()
  result=view.snapshot()
  print(json.dumps({'state':result['state'],'confirmed':result['sensor_heartbeat']['confirmed'],'no_traffic_observed':result['no_traffic_observed']}))
 finally: await db.close()
asyncio.run(main())
"""
    env = {key: value for key, value in os.environ.items() if not key.startswith("NETWATCHER_DB_")}
    env["NETWATCHER_SKIP_DOTENV"] = "1"
    child = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", code, str(config.config_path), str(Path(__file__).resolve().parents[2]),
        cwd=Path(__file__).resolve().parents[2], env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        async with asyncio.timeout(10):
            stdout, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-1000:]
        assert json.loads(stdout) == {"state": "partial", "confirmed": True, "no_traffic_observed": False}
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()
