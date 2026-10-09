"""실제 센서 실행 소유권 갱신과 확인 실패 시 입력 중단."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from netwatcher.services.sensor_state import SensorStatePublisher
from netwatcher.storage.sensor_state import SensorStateRepository, SensorLeaseLost


@pytest.mark.asyncio
async def test_stop_preserves_caller_cancellation_and_allows_later_release(db, monkeypatch):
    repository = SensorStateRepository(db)
    publisher = SensorStatePublisher(repository, "office", lambda: {"state": "partial"}, lambda: None)
    entered, release = asyncio.Event(), asyncio.Event()
    original = publisher._run
    async def delayed_shutdown():
        try:
            await original()
        except asyncio.CancelledError:
            entered.set()
            await release.wait()
            raise
    monkeypatch.setattr(publisher, "_run", delayed_shutdown)
    await publisher.start()
    child = publisher._task
    stopper = asyncio.create_task(publisher.stop())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        stopper.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stopper
        assert child.done()
        await publisher.stop()
        assert (await repository.read("office"))["stale"] is True
    finally:
        release.set()
        if not stopper.done():
            stopper.cancel()
        await asyncio.gather(stopper, child, return_exceptions=True)
        await publisher.stop()


@pytest.mark.asyncio
async def test_publisher_updates_snapshot_and_marks_stop(db):
    repo = SensorStateRepository(db)
    snapshot = {"state": "unknown"}
    stopped = []
    publisher = SensorStatePublisher(repo, "mirror-a", lambda: dict(snapshot), lambda: stopped.append(True), interval=1)
    await publisher.start()
    try:
        snapshot["state"] = "partial"
        await publisher.publish_once()
        row = await repo.read("mirror-a")
        assert row["snapshot"] == {"state": "partial"} and row["stale"] is False
        assert not stopped and not publisher.lost
    finally:
        await publisher.stop()
    assert (await repo.read("mirror-a"))["stale"] is True


@pytest.mark.asyncio
async def test_publisher_stops_input_when_owner_changes_and_cannot_stop_new_owner(db):
    repo = SensorStateRepository(db)
    stopped = asyncio.Event()
    publisher = SensorStatePublisher(repo, "mirror-a", lambda: {"state": "partial"}, stopped.set, interval=1)
    await publisher.start()
    owner = uuid4()
    try:
        await db.pool.execute("UPDATE sensor_runtime_state SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'")
        await repo.claim("mirror-a", owner)
        await asyncio.wait_for(stopped.wait(), 3)
        assert publisher.lost
        with pytest.raises(SensorLeaseLost):
            await publisher.publish_once()
    finally:
        await publisher.stop()
    assert (await repo.read("mirror-a"))["stale"] is False
    assert await db.pool.fetchval("SELECT owner FROM sensor_runtime_state") == owner


@pytest.mark.asyncio
async def test_committed_snapshot_with_lost_reply_stops_input_and_is_not_retried(db, monkeypatch):
    repo = SensorStateRepository(db)
    stopped = []
    publisher = SensorStatePublisher(repo, "mirror-a", lambda: {"state": "partial"}, lambda: stopped.append(True), interval=1)
    await publisher.start()
    calls = []
    original = repo.publish
    async def lose_reply(*args, **kwargs):
        await original(*args, **kwargs)
        calls.append(True)
        raise OSError("Injected reply loss")
    monkeypatch.setattr(repo, "publish", lose_reply)
    try:
        with pytest.raises(SensorLeaseLost):
            await publisher.publish_once()
        await asyncio.sleep(1.1)
        assert calls == [True] and stopped == [True] and publisher.lost
        assert (await repo.read("mirror-a"))["snapshot"] == {"state": "partial"}
    finally:
        await publisher.stop()


@pytest.mark.asyncio
async def test_rejected_duplicate_publisher_does_not_stop_current_owner(db):
    repo = SensorStateRepository(db)
    owner = uuid4()
    await repo.claim("mirror-a", owner)
    publisher = SensorStatePublisher(repo, "mirror-a", lambda: {}, lambda: None, interval=1)
    try:
        with pytest.raises(SensorLeaseLost):
            await publisher.start()
    finally:
        await publisher.stop()
    assert (await repo.read("mirror-a"))["stale"] is False
    assert await db.pool.fetchval("SELECT owner FROM sensor_runtime_state") == owner


@pytest.mark.parametrize("interval,lease", [(True, 30), (0, 30), (float('nan'), 30), (5, 10), (1, True), (1, 121)])
def test_invalid_heartbeat_configuration_is_rejected(interval, lease):
    with pytest.raises(ValueError):
        SensorStatePublisher(SimpleNamespace(), "mirror-a", lambda: {}, lambda: None, interval=interval, lease_seconds=lease)
