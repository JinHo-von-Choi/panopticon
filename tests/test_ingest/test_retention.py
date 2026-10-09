"""용량 초과의 읽기 위치 보존과 기간 정리의 원자성을 검증한다."""

import json

import asyncpg
import pytest

from netwatcher.ingest.repository import EveCapacityError, EveRepository
from netwatcher.ingest.tailer import EveTailer


def line(number=1):
    return json.dumps({"timestamp": "2026-10-08T01:00:00Z", "event_type": "alert",
                       "alert": {"signature_id": number, "severity": 2}}).encode() + b"\n"


def reader(db, directory, **budget):
    return EveTailer(EveRepository(db, **budget), directory=directory, sensor_id="sensor-1", source_id="office")


@pytest.mark.asyncio
async def test_service_automatically_frees_expired_capacity(db, tmp_path):
    import asyncio
    from netwatcher.ingest.service import EveService

    path = tmp_path / "eve.json"
    path.write_bytes(line())
    service = EveService(db, [{"directory": tmp_path, "sensor_id": "sensor-1", "source_id": "office"}],
                         retention={"max_records": 1, "cleanup_interval_seconds": 1})
    await service.start()
    try:
        async with asyncio.timeout(5):
            while await db.pool.fetchval("SELECT count(*) FROM events") != 1:
                await asyncio.sleep(0.01)
        with path.open("ab") as stream:
            stream.write(line(2))
        async with asyncio.timeout(5):
            while service.collectors[0].last_error != "EveCapacityError":
                await asyncio.sleep(0.01)
        await db.pool.execute("UPDATE eve_records SET received_at=NOW()-INTERVAL '31 days'")
        async with asyncio.timeout(5):
            while await db.pool.fetchval("SELECT count(*) FROM eve_records WHERE record->'details'->>'signature_id'='2'") != 1:
                await asyncio.sleep(0.01)
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_capacity_preserves_checkpoint_and_recovers_after_expiry(db, tmp_path):
    path = tmp_path / "eve.json"
    path.write_bytes(line())
    tailer = reader(db, tmp_path, max_records=1)
    try:
        await tailer.poll_once()
        before = await tailer.repository.load("sensor-1", "office")
        with path.open("ab") as stream:
            stream.write(line(2))
        with pytest.raises(EveCapacityError):
            await tailer.poll_once()
        assert await tailer.repository.load("sensor-1", "office") == before
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
        assert (await tailer.repository.storage_status("sensor-1", "office"))["records"] == 1
        await db.pool.execute("UPDATE eve_records SET received_at=NOW()-INTERVAL '31 days'")
        assert await tailer.repository.prune("sensor-1", "office") == 1
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 0
        assert await db.pool.fetchval("SELECT count(*) FROM event_ingest") == 0
        assert await tailer.poll_once() == 1
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
        assert (await tailer.repository.storage_status("sensor-1", "office"))["records"] == 1
    finally:
        tailer.close()


@pytest.mark.asyncio
async def test_byte_budget_failure_does_not_create_records_or_cursor(db, tmp_path):
    (tmp_path / "eve.json").write_bytes(line())
    tailer = reader(db, tmp_path, max_bytes=1024)
    try:
        with pytest.raises(EveCapacityError):
            await tailer.poll_once()
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 0
        assert await tailer.repository.load("sensor-1", "office") == (None, None)
        status = await tailer.repository.storage_status("sensor-1", "office")
        assert status["records"] == status["accounted_bytes"] == 0
        assert status["physical_disk_bytes"] is None
    finally:
        tailer.close()


@pytest.mark.asyncio
async def test_pruning_is_bounded_and_rolls_back_when_event_delete_fails(db, tmp_path):
    (tmp_path / "eve.json").write_bytes(line(1) + line(2) + line(3))
    tailer = reader(db, tmp_path)
    try:
        await tailer.poll_once()
        assert await tailer.repository.prune("sensor-1", "office") == 0
        await db.pool.execute("UPDATE eve_records SET received_at=NOW()-INTERVAL '31 days'")
        await db.pool.execute("""CREATE FUNCTION prevent_event_delete() RETURNS trigger AS $$
            BEGIN RAISE EXCEPTION 'injected retention failure'; END; $$ LANGUAGE plpgsql;
            CREATE TRIGGER prevent_event_delete BEFORE DELETE ON events
            FOR EACH ROW EXECUTE FUNCTION prevent_event_delete();""")
        before = await tailer.repository.storage_status("sensor-1", "office")
        with pytest.raises(asyncpg.RaiseError):
            await tailer.repository.prune("sensor-1", "office", limit=1)
        assert await tailer.repository.storage_status("sensor-1", "office") == before
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 3
        await db.pool.execute("DROP TRIGGER prevent_event_delete ON events")
        assert await tailer.repository.prune("sensor-1", "office", limit=1) == 1
        assert (await tailer.repository.storage_status("sensor-1", "office"))["records"] == 2
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 2
    finally:
        tailer.close()
