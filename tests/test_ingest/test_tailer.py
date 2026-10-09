"""실제 파일과 PostgreSQL로 EVE 복구·저장 경계를 검증한다."""

import json

import pytest

from netwatcher.ingest.repository import EveRepository, StaleCheckpointError
from netwatcher.ingest.tailer import EveTailer


def line(signature=100):
    return json.dumps({"timestamp": "2026-10-08T10:00:00+0900", "event_type": "alert",
                       "src_ip": "192.0.2.10", "alert": {"signature_id": signature,
                       "severity": 2, "signature": f"Alert {signature}"}}).encode() + b"\n"


def tailer(db, directory):
    return EveTailer(EveRepository(db), directory=directory, sensor_id="sensor-1",
                     source_id="office", rotation_grace=0)


@pytest.mark.asyncio
async def test_partial_line_restart_and_rotation_preserve_alerts(db, tmp_path):
    path = tmp_path / "eve.json"
    data = line()
    path.write_bytes(data[:-1])
    reader = tailer(db, tmp_path)
    try:
        assert await reader.poll_once() == 0
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 0
        with path.open("ab") as stream:
            stream.write(b"\n")
        assert await reader.poll_once() == 1
        event = await db.pool.fetchrow("SELECT severity, metadata, timestamp FROM events")
        assert event["severity"] == "WARNING"
        assert event["metadata"]["external_eve"]["details"]["severity"] == 2
        assert str(event["timestamp"]).startswith("2026-10-08 01:00:00") or str(event["timestamp"]).startswith("2026-10-08T01:00:00")
    finally:
        reader.close()
    path.rename(tmp_path / "eve.json.1")
    with (tmp_path / "eve.json.1").open("ab") as stream:
        stream.write(line(101))
    path.write_bytes(line(102))
    reader = tailer(db, tmp_path)
    try:
        assert await reader.poll_once() == 1  # 재시작해도 이전 파일의 나머지를 읽는다.
        await reader.poll_once()  # 이전 파일 EOF 확인 후 새 세대 선택
        assert await reader.poll_once() == 1
        assert await reader.poll_once() == 0
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 3
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 3
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_failed_projection_rolls_back_records_and_checkpoint(db, tmp_path, monkeypatch):
    (tmp_path / "eve.json").write_bytes(line())
    reader = tailer(db, tmp_path)
    original = reader.repository._events.insert_batch_mapped
    async def fail(*args, **kwargs):
        raise RuntimeError("injected projection failure")
    monkeypatch.setattr(reader.repository._events, "insert_batch_mapped", fail)
    try:
        with pytest.raises(RuntimeError):
            await reader.poll_once()
        assert await db.pool.fetchval("SELECT count(*) FROM eve_checkpoints") == 0
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 0
        monkeypatch.setattr(reader.repository._events, "insert_batch_mapped", original)
        assert await reader.poll_once() == 1
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_copy_truncate_and_invalid_line_are_visible(db, tmp_path):
    path = tmp_path / "eve.json"
    path.write_bytes(line(100))
    reader = tailer(db, tmp_path)
    try:
        await reader.poll_once()
        path.write_bytes(b"invalid-json\n" + line(101))
        assert await reader.poll_once() == 3
        reasons = await db.pool.fetch("SELECT record->>'reason' AS reason FROM eve_records WHERE event_type LIKE '\\_%' ESCAPE '\\'")
        assert {row["reason"] for row in reasons} == {"copy_truncate", "invalid_record"}
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 2
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_duplicate_and_stale_checkpoint_do_not_reapply(db, tmp_path):
    (tmp_path / "eve.json").write_bytes(line())
    reader = tailer(db, tmp_path)
    try:
        await reader.poll_once()
        revision, state = await reader.repository.load("sensor-1", "office")
        row = await db.pool.fetchrow("SELECT record FROM eve_records")
        next_revision = await reader.repository.commit("sensor-1", "office", revision, state, [row["record"]])
        assert next_revision == revision + 1
        with pytest.raises(StaleCheckpointError):
            await reader.repository.commit("sensor-1", "office", revision, state, [row["record"]])
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_symlink_input_is_rejected(db, tmp_path):
    target = tmp_path / "source.json"
    target.write_bytes(line())
    (tmp_path / "eve.json").symlink_to(target)
    reader = tailer(db, tmp_path)
    try:
        with pytest.raises(OSError):
            await reader.poll_once()
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 0
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_lost_commit_response_resumes_from_database(db, tmp_path, monkeypatch):
    (tmp_path / "eve.json").write_bytes(line())
    reader = tailer(db, tmp_path)
    original = reader.repository.commit
    async def committed_but_response_lost(*args):
        await original(*args)
        raise ConnectionError("lost commit response")
    monkeypatch.setattr(reader.repository, "commit", committed_but_response_lost)
    try:
        with pytest.raises(ConnectionError):
            await reader.poll_once()
        monkeypatch.setattr(reader.repository, "commit", original)
        assert await reader.poll_once() == 0
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_oversized_line_is_bounded_and_following_alert_survives(db, tmp_path):
    from netwatcher.ingest.eve import MAX_LINE_BYTES
    (tmp_path / "eve.json").write_bytes(b"x" * (2 * MAX_LINE_BYTES + 100) + b"\n" + line())
    reader = tailer(db, tmp_path)
    try:
        await reader.poll_once()
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
        record = await db.pool.fetchval("SELECT record FROM eve_records WHERE event_type='_rejected'")
        assert record["reason"] == "line_too_large"
        assert record["original_ref"]["partial"] is True
        assert len(json.dumps(record)) < 1024
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_missing_rotated_source_is_recorded_on_restart(db, tmp_path):
    path = tmp_path / "eve.json"
    path.write_bytes(line())
    reader = tailer(db, tmp_path)
    await reader.poll_once()
    reader.close()
    path.rename(tmp_path / "old.json")
    path.write_bytes(line(101))
    (tmp_path / "old.json").unlink()
    reader = tailer(db, tmp_path)
    try:
        assert await reader.poll_once() == 2
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records WHERE record->>'reason'='rotated_source_missing'") == 1
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 2
    finally:
        reader.close()


@pytest.mark.asyncio
async def test_multiple_sources_continue_when_one_file_is_missing(db, tmp_path):
    import asyncio
    from netwatcher.ingest.service import EveService

    (tmp_path / "good.json").write_bytes(line())
    service = EveService(db, [
        {"directory": tmp_path, "filename": "good.json", "sensor_id": "sensor-1", "source_id": "good"},
        {"directory": tmp_path, "filename": "missing.json", "sensor_id": "sensor-1", "source_id": "missing"},
    ])
    await service.start()
    try:
        async with asyncio.timeout(5):
            while (service.collectors[0].last_poll is None or service.collectors[1].last_error is None or
                   await db.pool.fetchval("SELECT count(*) FROM events") == 0):
                await asyncio.sleep(0.01)
        result = service.status()
        assert result["status"] == "unhealthy"
        assert result["packet_capture"] is False
        assert result["sources"][0]["status"] == "healthy"
        assert result["sources"][1]["error"] == "FileNotFoundError"
        assert result["sources"][0]["capture_loss"] == "unknown"
    finally:
        await service.stop()
    assert service.status()["status"] == "unhealthy"
    assert all(collector._file_fd is None and collector._directory_fd is None for collector in service.collectors)
