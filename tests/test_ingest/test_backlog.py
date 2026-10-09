"""실제 입력 파일의 수집 대기와 바이트 상한 뒤의 진행을 확인한다."""

import asyncio
import json

import pytest

from netwatcher.ingest.eve import MAX_LINE_BYTES
from netwatcher.ingest.tailer import EveTailer


def alert_line():
    return json.dumps({"timestamp": "2026-10-09T01:00:00Z", "event_type": "alert",
        "alert": {"signature_id": 1, "severity": 2, "signature": "Backlog fixture"},
        "extra": "x" * 8192}).encode() + b"\n"


class Repository:
    def __init__(self, stop=None, end=None):
        self.revision = 0
        self.records = 0
        self.stop, self.end = stop, end

    async def load(self, *identity):
        return None, None

    async def commit(self, sensor, source, revision, state, records):
        self.revision += 1
        self.records += len(records)
        await asyncio.sleep(0)
        if self.stop is not None and state["offset"] == self.end:
            self.stop.set()
        return self.revision


def reader(repository, tmp_path, **settings):
    return EveTailer(repository, directory=tmp_path, sensor_id="fixture", source_id="input", **settings)


@pytest.mark.asyncio
async def test_real_unread_bytes_expose_backlog_then_clear_after_drain(tmp_path):
    line = alert_line()
    contents = line * 300
    (tmp_path / "eve.json").write_bytes(contents)
    source = reader(Repository(), tmp_path, batch_records=1, batch_bytes=MAX_LINE_BYTES + 1)
    try:
        assert await source.poll_once() == 1
        state = source.status()
        assert state["pending_bytes"] == len(contents) - len(line)
        assert state["pending_scope"] == "active_file"
        assert state["backlog"] and state["status"] == "degraded"
        assert state["gaps"] == state["rejected"] == 0
        source.batch_records = 1024
        while await source.poll_once():
            pass
        state = source.status()
        assert state["pending_bytes"] == 0
        assert not state["backlog"] and state["status"] == "healthy"
    finally:
        source.close()


@pytest.mark.asyncio
async def test_truncated_or_closed_position_is_unknown_not_zero(tmp_path):
    path = tmp_path / "eve.json"
    path.write_bytes(alert_line())
    source = reader(Repository(), tmp_path)
    try:
        await source.poll_once()
        assert source.status()["pending_bytes"] == 0
        path.write_bytes(b"")
        assert source.status()["pending_bytes"] is None
        assert source.status()["status"] == "degraded"
        source.close()
        assert source.status()["pending_bytes"] is None
    finally:
        source.close()


@pytest.mark.asyncio
async def test_byte_limited_batches_drain_without_waiting_poll_interval(tmp_path):
    contents = alert_line() * 300
    (tmp_path / "eve.json").write_bytes(contents)
    stop = asyncio.Event()
    repository = Repository(stop, len(contents))
    source = reader(repository, tmp_path, batch_records=1024, batch_bytes=MAX_LINE_BYTES + 1)
    async with asyncio.timeout(5):
        await source.run(stop, interval=30)
    assert repository.records == 300
    assert source._state["offset"] == len(contents)


@pytest.mark.asyncio
async def test_incomplete_last_line_does_not_spin(tmp_path, monkeypatch):
    contents = alert_line() * 300 + b'{"timestamp":'
    (tmp_path / "eve.json").write_bytes(contents)
    source = reader(Repository(), tmp_path, batch_records=1024, batch_bytes=MAX_LINE_BYTES + 1)
    stop = asyncio.Event()
    polled = 0
    original = source.poll_once
    reached_partial = asyncio.Event()

    async def count_poll():
        nonlocal polled
        polled += 1
        result = await original()
        if source._state["offset"] == len(contents) - len(b'{"timestamp":'):
            reached_partial.set()
        return result

    monkeypatch.setattr(source, "poll_once", count_poll)
    task = asyncio.create_task(source.run(stop, interval=30))
    try:
        async with asyncio.timeout(5):
            await reached_partial.wait()
        before = polled
        await asyncio.sleep(.1)
        assert polled == before
    finally:
        stop.set()
        async with asyncio.timeout(5):
            await task
