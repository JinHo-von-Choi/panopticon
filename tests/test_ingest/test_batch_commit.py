"""다중행 저장의 사건 연결·용량·충돌·롤백 경계를 확인한다."""

import copy
import json
import os
from types import SimpleNamespace

import pytest

from netwatcher.ingest.repository import EveRepository, EveCapacityError, StaleCheckpointError
from netwatcher.ingest.tailer import EveTailer


def reader(db, tmp_path, stream, **budget):
    lines = []
    for index in range(64):
        data = {"timestamp": "2026-10-08T01:00:00Z", "event_type": "flow"}
        if index % 2 == 0:
            data.update(event_type="alert", alert={"signature_id": index + 1,
                        "severity": 2, "signature": f"Synthetic {index + 1}"})
        lines.append(json.dumps(data) + "\n")
    (tmp_path / "eve.json").write_text("".join(lines))
    return EveTailer(EveRepository(db, stream, **budget), directory=tmp_path,
                     sensor_id="batch-test", source_id="synthetic-file")


@pytest.mark.asyncio
async def test_mixed_batch_links_correct_events_and_reads_file_in_bounded_chunks(db, tmp_path, monkeypatch):
    published = []
    tailer = reader(db, tmp_path, SimpleNamespace(publish=published.append))
    original = os.pread
    reads = []
    def observe(descriptor, size, offset):
        reads.append(size)
        return original(descriptor, size, offset)
    monkeypatch.setattr(os, "pread", observe)
    project = tailer.repository._project_records
    writes = {}
    async def observe_projection(conn, records, **kwargs):
        result = await project(conn, records, **kwargs)
        row = await conn.fetchrow("""SELECT n_tup_ins,n_tup_upd FROM pg_stat_xact_user_tables
                                   WHERE relid='eve_records'::regclass""")
        writes.update(dict(row))
        return result
    monkeypatch.setattr(tailer.repository, "_project_records", observe_projection)
    try:
        assert await tailer.poll_once() == 64
        assert writes == {"n_tup_ins": 64, "n_tup_upd": 0}
        assert len(reads) < 10  # 행마다 같은 대형 블록을 다시 읽지 않는다.
        rows = await db.pool.fetch("""SELECT r.record,r.event_id,e.title FROM eve_records r
            LEFT JOIN events e ON e.id=r.event_id ORDER BY r.record->'original_ref'->>'offset'""")
        assert len(rows) == 64
        alerts = [row for row in rows if row["record"]["event_type"] == "alert"]
        assert len(alerts) == len(published) == 32
        for row in alerts:
            assert row["title"] == f"Synthetic {row['record']['details']['signature_id']}"
            assert any(event["id"] == row["event_id"] and event["title"] == row["title"] for event in published)
        assert all(row["event_id"] is None for row in rows if row["record"]["event_type"] == "flow")
        assert (await tailer.repository.storage_status("batch-test", "synthetic-file"))["records"] == 64
    finally:
        tailer.close()


@pytest.mark.asyncio
async def test_existing_event_identity_cannot_create_an_unrelated_eve_link(db, tmp_path):
    published = []
    tailer = reader(db, tmp_path, SimpleNamespace(publish=published.append))
    try:
        state, records = tailer._read_batch()
        alert = next(record for record in records if record["event_type"] == "alert")
        original = await tailer.repository._events.insert_batch_mapped([
            {"ingest_id": alert["ingest_id"], "title": "Existing event"}])
        with pytest.raises(ValueError, match="reserved link"):
            await tailer.repository.commit("batch-test", "synthetic-file", None, state, records)
        assert await tailer.repository.load("batch-test", "synthetic-file") == (None, None)
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 0
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
        assert await db.pool.fetchval("SELECT title FROM events WHERE id=$1", next(iter(original.values()))) == "Existing event"
        assert published == []
    finally:
        tailer.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["capacity", "projection"])
async def test_whole_batch_failure_preserves_cursor_and_does_not_publish(db, tmp_path, monkeypatch, failure):
    published = []
    tailer = reader(db, tmp_path, SimpleNamespace(publish=published.append),
                    **({"max_records": 63} if failure == "capacity" else {}))
    if failure == "projection":
        async def fail(*args, **kwargs):
            raise RuntimeError("injected batch projection failure")
        monkeypatch.setattr(tailer.repository._events, "insert_batch_mapped", fail)
    else:
        async def reject_write(*args, **kwargs):
            raise AssertionError("over-capacity input must not reach INSERT")
        monkeypatch.setattr(tailer.repository, "_insert_records", reject_write)
    try:
        with pytest.raises(EveCapacityError if failure == "capacity" else RuntimeError):
            await tailer.poll_once()
        assert await tailer.repository.load("batch-test", "synthetic-file") == (None, None)
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 0
        assert await db.pool.fetchval("SELECT count(*) FROM events") == 0
        assert published == []
    finally:
        tailer.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("budget", ["records", "bytes"])
async def test_full_budget_allows_only_duplicates_and_preserves_failed_cursor(db, tmp_path, monkeypatch, budget):
    published = []
    tailer = reader(db, tmp_path, SimpleNamespace(publish=published.append), max_records=64)
    try:
        assert await tailer.poll_once() == 64
        if budget == "bytes":
            usage = await tailer.repository.storage_status("batch-test", "synthetic-file")
            tailer.repository.max_records = 65
            tailer.repository.max_bytes = usage["accounted_bytes"]
        revision, state = await tailer.repository.load("batch-test", "synthetic-file")
        records = [row["record"] for row in await db.pool.fetch("SELECT record FROM eve_records")]
        revision = await tailer.repository.commit("batch-test", "synthetic-file", revision, state, records + records)
        assert len(published) == 32
        with (tmp_path / "eve.json").open('a') as stream:
            stream.write(json.dumps({"timestamp": "2026-10-08T01:00:00Z", "event_type": "flow"}) + '\n')
        async def reject_write(*args, **kwargs):
            raise AssertionError("full storage must reject fresh input before INSERT")
        monkeypatch.setattr(tailer.repository, "_insert_records", reject_write)
        # 다른 저장자가 갱신한 위치는 먼저 재조회하고 다음 시도에 한도를 검사한다.
        with pytest.raises(StaleCheckpointError):
            await tailer.poll_once()
        for _ in range(3):
            with pytest.raises(EveCapacityError):
                await tailer.poll_once()
        assert await tailer.repository.load("batch-test", "synthetic-file") == (revision, state)
        assert await db.pool.fetchval("SELECT count(*) FROM eve_records") == 64
        assert len(published) == 32
    finally:
        tailer.close()


@pytest.mark.asyncio
async def test_duplicates_do_not_recharge_or_publish_and_hash_conflict_rolls_back(db, tmp_path):
    published = []
    tailer = reader(db, tmp_path, SimpleNamespace(publish=published.append))
    try:
        await tailer.poll_once()
        revision, state = await tailer.repository.load("batch-test", "synthetic-file")
        records = [row["record"] for row in await db.pool.fetch("SELECT record FROM eve_records")]
        revision = await tailer.repository.commit("batch-test", "synthetic-file", revision, state, records + records)
        assert len(published) == 32
        before = await tailer.repository.storage_status("batch-test", "synthetic-file")
        assert before["records"] == 64
        conflict = copy.deepcopy(records[0])
        conflict["original_ref"]["sha256"] = "0" * 64
        with pytest.raises(ValueError, match="different source content"):
            await tailer.repository.commit("batch-test", "synthetic-file", revision, state, [conflict])
        assert await tailer.repository.load("batch-test", "synthetic-file") == (revision, state)
        assert await tailer.repository.storage_status("batch-test", "synthetic-file") == before
        assert len(published) == 32
    finally:
        tailer.close()
