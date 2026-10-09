"""실제 DB의 센서 임대를 바꾸지 않는 콘솔 관측 조회 수명주기."""

import asyncio
from uuid import uuid4

import httpx
import pytest

from netwatcher.alerts.stream import EventStream
from netwatcher.services.sensor_state import SensorObservationReader
from netwatcher.storage.repositories import DeviceRepository, EventRepository, TrafficStatsRepository
from netwatcher.storage.sensor_state import SensorStateRepository, StoredSensorObservation
from netwatcher.web.server import create_app


async def wait_until(predicate):
    async with asyncio.timeout(4):
        while not predicate():
            await asyncio.sleep(.02)


@pytest.mark.asyncio
async def test_periodic_reader_updates_http_without_claim_or_lease_write(db, config):
    repository = SensorStateRepository(db)
    owner = uuid4()
    await repository.claim("office", owner)
    await repository.publish("office", owner, {"state": "partial", "no_traffic_observed": False,
                                               "reasons": ["SPAN 관측 범위를 확인해야 합니다."]})
    observation = StoredSensorObservation(repository, "office")
    reader = SensorObservationReader(observation, interval=1)
    app = create_app(config, EventRepository(db), DeviceRepository(db), TrafficStatsRepository(db),
                     EventStream(), observation_service=observation)
    await reader.start()
    try:
        before = await db.pool.fetchrow("SELECT * FROM sensor_runtime_state WHERE sensor_id='office'")
        await asyncio.sleep(1.1)
        after = await db.pool.fetchrow("SELECT * FROM sensor_runtime_state WHERE sensor_id='office'")
        assert after == before
        assert reader.status()["status"] == "healthy"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/observation")
            assert response.status_code == 200
            assert response.json()["state"] == "partial"
            await repository.release("office", owner)
            await wait_until(lambda: observation.snapshot()["state"] == "stale")
            response = await client.get("/api/observation")
            assert response.json()["state"] == "stale"
            assert response.json()["no_traffic_observed"] is None
            assert response.json()["sensor_heartbeat"]["confirmed"] is False
        assert reader.status()["status"] == "degraded"
    finally:
        await reader.stop()
    assert reader.status()["status"] == "unhealthy"
    assert observation.snapshot()["sensor_heartbeat"]["confirmed"] is False


@pytest.mark.asyncio
async def test_reader_recovers_database_failure_without_log_flood(db, caplog):
    repository = SensorStateRepository(db)
    owner = uuid4()
    await repository.claim("office", owner)
    await repository.publish("office", owner, {"state": "observed"})
    observation = StoredSensorObservation(repository, "office")
    reader = SensorObservationReader(observation, interval=1)
    await reader.start()
    renamed = False
    try:
        await db.pool.execute("ALTER TABLE sensor_runtime_state RENAME TO sensor_runtime_state_read_test")
        renamed = True
        await wait_until(lambda: reader.status()["status"] == "unhealthy")
        assert observation.snapshot()["state"] == "stale"
        await asyncio.sleep(1.1)
        warnings = [record for record in caplog.records if record.message.startswith("Sensor observation read failed")]
        assert len(warnings) == 1
        await db.pool.execute("ALTER TABLE sensor_runtime_state_read_test RENAME TO sensor_runtime_state")
        renamed = False
        await wait_until(lambda: reader.status()["status"] == "healthy")
        assert observation.snapshot()["state"] == "observed"
        assert observation.snapshot()["sensor_heartbeat"]["confirmed"] is True
    finally:
        if renamed:
            await db.pool.execute("ALTER TABLE sensor_runtime_state_read_test RENAME TO sensor_runtime_state")
        await reader.stop()


@pytest.mark.asyncio
async def test_startup_without_sensor_stays_unknown_then_recovers(db):
    repository = SensorStateRepository(db)
    observation = StoredSensorObservation(repository, "office")
    reader = SensorObservationReader(observation, interval=1)
    await reader.start()
    task = reader._task
    try:
        await reader.start()
        assert reader._task is task
        assert reader.status()["status"] == "degraded"
        assert observation.snapshot()["state"] == "unknown"
        assert await db.pool.fetchval("SELECT count(*) FROM sensor_runtime_state") == 0
        owner = uuid4()
        await repository.claim("office", owner)
        await repository.publish("office", owner, {"state": "partial"})
        await wait_until(lambda: reader.status()["status"] == "healthy")
        await reader.stop()
        assert task.done()
        assert observation.snapshot()["state"] == "stale"
        await reader.start()
        assert reader._task is not task
        assert reader.status()["status"] == "healthy"
    finally:
        await reader.stop()
        await reader.stop()


@pytest.mark.asyncio
async def test_stop_cancels_active_read_and_cannot_reconfirm_old_cache(db, monkeypatch):
    repository = SensorStateRepository(db)
    owner = uuid4()
    await repository.claim("office", owner)
    await repository.publish("office", owner, {"state": "partial"})
    observation = StoredSensorObservation(repository, "office")
    reader = SensorObservationReader(observation, interval=1)
    await reader.start()
    entered, blocked = asyncio.Event(), asyncio.Event()
    original = repository.read
    async def delayed(sensor_id):
        row = await original(sensor_id)
        entered.set()
        await blocked.wait()
        return row
    monkeypatch.setattr(repository, "read", delayed)
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task = reader._task
        await reader.stop()
        assert task.done()
        assert observation.snapshot()["state"] == "stale"
        assert observation.snapshot()["sensor_heartbeat"]["confirmed"] is False
        assert (await original("office"))["stale"] is False
    finally:
        await reader.stop()


@pytest.mark.asyncio
async def test_stop_invalidates_a_separate_inflight_refresh(db, monkeypatch):
    repository = SensorStateRepository(db)
    owner = uuid4()
    await repository.claim("office", owner)
    await repository.publish("office", owner, {"state": "partial"})
    observation = StoredSensorObservation(repository, "office")
    reader = SensorObservationReader(observation, interval=1)
    await reader.start()
    entered, release = asyncio.Event(), asyncio.Event()
    original = repository.read
    async def delayed(sensor_id):
        row = await original(sensor_id)
        entered.set()
        await release.wait()
        return row
    monkeypatch.setattr(repository, "read", delayed)
    task = asyncio.create_task(observation.refresh())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await reader.stop()
        release.set()
        await task
        assert observation.snapshot()["state"] == "stale"
        assert observation.snapshot()["sensor_heartbeat"]["confirmed"] is False
        monkeypatch.setattr(repository, "read", original)
        await observation.refresh()
        assert observation.snapshot()["state"] == "partial"
        assert observation.snapshot()["sensor_heartbeat"]["confirmed"] is True
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await reader.stop()


@pytest.mark.parametrize("option,value", [("interval", True), ("interval", .1), ("interval", 11),
    ("timeout_seconds", True), ("timeout_seconds", .01), ("timeout_seconds", 3),
    ("timeout_seconds", float("nan"))])
def test_reader_rejects_unbounded_or_invalid_settings(option, value):
    observation = StoredSensorObservation(None, "office")
    with pytest.raises(ValueError):
        SensorObservationReader(observation, **{option:value})


@pytest.mark.asyncio
async def test_stop_propagates_caller_cancellation_after_requesting_child_stop(db, monkeypatch):
    repository = SensorStateRepository(db)
    owner = uuid4()
    await repository.claim("office", owner)
    await repository.publish("office", owner, {"state": "partial"})
    observation = StoredSensorObservation(repository, "office")
    reader = SensorObservationReader(observation, interval=1)
    entered, release = asyncio.Event(), asyncio.Event()
    original = reader._run
    async def delayed_shutdown():
        try:
            await original()
        except asyncio.CancelledError:
            entered.set()
            await release.wait()
            raise
    monkeypatch.setattr(reader, "_run", delayed_shutdown)
    await reader.start()
    child = reader._task
    stopper = asyncio.create_task(reader.stop())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        stopper.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stopper
        assert child.done()
        assert reader.status()["status"] == "unhealthy"
        assert observation.snapshot()["sensor_heartbeat"]["confirmed"] is False
        assert (await repository.read("office"))["stale"] is False
    finally:
        release.set()
        if not stopper.done():
            stopper.cancel()
        await asyncio.gather(stopper, child, return_exceptions=True)
        await reader.stop()
