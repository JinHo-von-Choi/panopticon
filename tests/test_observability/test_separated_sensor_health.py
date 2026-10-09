"""실제 DB 임대와 사건 전달 연결을 사용하는 독립 콘솔 준비 상태."""

from uuid import uuid4

import pytest
import pytest_asyncio

from netwatcher.alerts.database_stream import DatabaseEventStream
from netwatcher.observability.sensor_health import SeparatedSensorHealthChecker
from netwatcher.services.sensor_state import SensorObservationReader
from netwatcher.storage.sensor_state import SensorStateRepository, StoredSensorObservation


def snapshot():
    return {"state": "observed", "reasons": ["관측 창에 이상이 감지되지 않았습니다."], "no_traffic_observed": False, "runtime": {
        "capture_running": True,
        "health_components": {name: {"status": "healthy"}
                              for name in ("sniffer", "engines", "alert_queue", "stats_flush")}}}


@pytest_asyncio.fixture
async def sensor_health(db):
    repository = SensorStateRepository(db)
    owner = uuid4()
    await repository.claim("health-test", owner)
    observation = StoredSensorObservation(repository, "health-test")
    stream = DatabaseEventStream(db)
    await stream.start()
    try:
        yield SeparatedSensorHealthChecker(db, observation, stream), repository, owner, stream
    finally:
        await stream.stop()


@pytest.mark.asyncio
async def test_current_sensor_and_actual_listener_are_required(sensor_health):
    health, repository, owner, stream = sensor_health
    initial = await health.readiness()
    assert initial["ready"] is False
    assert initial["components"]["sniffer"]["status"] == "unknown"
    await repository.publish("health-test", owner, snapshot())
    result = await health.readiness()
    assert result["ready"] is True
    assert result["components"]["sensor_state"]["scope"] == "separate_sensor"
    assert result["components"]["event_stream"]["status"] == "healthy"
    await stream.stop()
    result = await health.readiness()
    assert result["ready"] is False
    assert result["components"]["event_stream"]["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_active_manual_query_cannot_hide_stopped_reader(sensor_health):
    health, repository, owner, stream = sensor_health
    await repository.publish("health-test", owner, snapshot())
    reader = SensorObservationReader(health._observation, interval=1)
    health._observation_reader = reader
    assert (await health.readiness())["ready"] is False
    await reader.start()
    try:
        assert (await health.readiness())["ready"] is True
        await reader.stop()
        result = await health.readiness()
        assert result["ready"] is False
        assert result["components"]["sensor_state"]["status"] == "healthy"
        assert result["components"]["observation_reader"]["status"] == "unhealthy"
    finally:
        await reader.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("component", ["sniffer", "engines", "alert_queue", "stats_flush"])
async def test_sensor_failure_and_recovery(sensor_health, component):
    health, repository, owner, stream = sensor_health
    value = snapshot()
    value["runtime"]["health_components"][component]["status"] = "degraded"
    await repository.publish("health-test", owner, value)
    result = await health.readiness()
    assert result["ready"] is False
    assert result["components"][component]["status"] == "degraded"
    await repository.publish("health-test", owner, snapshot())
    assert (await health.readiness())["ready"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("runtime", [None, {}, {"capture_running": True},
    {"capture_running": True, "health_components": None}])
async def test_missing_runtime_does_not_invent_healthy_components(sensor_health, runtime):
    health, repository, owner, stream = sensor_health
    value = snapshot()
    value["runtime"] = runtime
    await repository.publish("health-test", owner, value)
    result = await health.readiness()
    assert result["ready"] is False
    assert all(result["components"][name]["status"] == "unknown" for name in health.sensor_components)


@pytest.mark.asyncio
@pytest.mark.parametrize("state", [None, ["observed"], {"state": "observed"}, "unsupported"])
async def test_invalid_observation_state_does_not_crash_or_confirm_health(sensor_health, state):
    health, repository, owner, stream = sensor_health
    value = snapshot()
    value["state"] = state
    await repository.publish("health-test", owner, value)
    result = await health.readiness()
    assert result["ready"] is False
    assert result["components"]["observation"]["state"] == "unknown"
    assert all(result["components"][name]["status"] == "unknown" for name in health.sensor_components)


@pytest.mark.asyncio
async def test_expiry_shutdown_and_replacement_do_not_reuse_old_health(sensor_health, db):
    health, repository, owner, stream = sensor_health
    await repository.publish("health-test", owner, snapshot())
    assert (await health.readiness())["ready"] is True
    await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
    expired = await health.readiness()
    assert expired["ready"] is False
    assert expired["components"]["observation"]["state"] == "stale"
    assert expired["components"]["engines"] == {"status": "unknown", "scope": "separate_sensor"}
    replacement = uuid4()
    await repository.claim("health-test", replacement)
    assert (await health.readiness())["ready"] is False
    await repository.publish("health-test", replacement, snapshot())
    assert (await health.readiness())["ready"] is True
    await repository.release("health-test", replacement)
    assert (await health.readiness())["ready"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("reasons", [None, [], [None], [""], "unsupported"])
async def test_observation_without_valid_reason_cannot_be_ready(sensor_health, reasons):
    health, repository, owner, stream = sensor_health
    value = snapshot()
    value["reasons"] = reasons
    await repository.publish("health-test", owner, value)
    result = await health.readiness()
    assert result["ready"] is False
    assert result["components"]["observation"]["state"] == "unknown"
    assert result["components"]["observation"]["reasons"]


@pytest.mark.asyncio
async def test_db_read_failure_does_not_keep_last_ready_state(sensor_health, monkeypatch):
    health, repository, owner, stream = sensor_health
    await repository.publish("health-test", owner, snapshot())
    assert (await health.readiness())["ready"] is True
    original = repository.read
    async def fail(_):
        raise OSError("test secret must not appear in response")
    monkeypatch.setattr(repository, "read", fail)
    result = await health.readiness()
    assert result["ready"] is False
    assert "test secret" not in str(result)
    assert result["components"]["engines"]["status"] == "unknown"
    monkeypatch.setattr(repository, "read", original)
    assert (await health.readiness())["ready"] is True


@pytest.mark.asyncio
async def test_partial_scope_and_stopped_capture_remain_unready(sensor_health):
    health, repository, owner, stream = sensor_health
    value = snapshot()
    value["state"] = "partial"
    value["reasons"] = ["SPAN 범위를 확인해야 합니다."]
    await repository.publish("health-test", owner, value)
    result = await health.readiness()
    assert result["ready"] is False
    assert result["components"]["observation"]["state"] == "partial"
    assert result["components"]["engines"]["status"] == "healthy"
    value = snapshot()
    value["runtime"]["capture_running"] = False
    await repository.publish("health-test", owner, value)
    result = await health.readiness()
    assert result["ready"] is False
    assert result["components"]["sniffer"]["status"] == "unknown"
