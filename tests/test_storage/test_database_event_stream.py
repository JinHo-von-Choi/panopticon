"""실제 DB 커밋 순서·롤백·연결 손실과 유한 경보 전달 시험."""

import asyncio
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

import pytest
import pytest_asyncio

from netwatcher.alerts.database_stream import DatabaseEventStream, notification_key
from netwatcher.alerts.stream import EventStream


@pytest_asyncio.fixture
async def stream_case(db):
    stream = DatabaseEventStream(db)
    await stream.start()
    queue = stream.subscribe_ws()
    try:
        yield stream, queue
    finally:
        await stream.stop()
        assert stream.status()["status"] == "unhealthy"


async def receive(queue, kind="alert"):
    async with asyncio.timeout(5):
        while True:
            event = json.loads(await queue.get())
            if event["type"] == kind:
                return event


async def insert(connection, title):
    return await connection.fetchval("INSERT INTO events(engine,severity,title) VALUES('port_scan','WARNING',$1) RETURNING id", title)


@pytest.mark.asyncio
async def test_late_low_id_commit_is_delivered_after_high_id(stream_case, db):
    _, queue = stream_case
    async with db.pool.acquire() as first:
        transaction = first.transaction()
        await transaction.start()
        try:
            low = await insert(first, "늦게 커밋한 경보")
            high = await insert(db.pool, "먼저 커밋한 경보")
            assert high > low
            assert (await receive(queue))["id"] == high
            await transaction.commit()
        except BaseException:
            if first.is_in_transaction():
                await transaction.rollback()
            raise
    event = await receive(queue)
    assert event["id"] == low and event["title"] == "늦게 커밋한 경보"


@pytest.mark.asyncio
async def test_rolled_back_event_is_not_delivered(stream_case, db):
    _, queue = stream_case
    async with db.pool.acquire() as conn:
        transaction = conn.transaction()
        await transaction.start()
        await insert(conn, "롤백한 경보")
        await transaction.rollback()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(queue.get(), .2)
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 0


@pytest.mark.asyncio
async def test_notification_is_not_an_event_and_must_match_stored_timestamp(stream_case, db):
    stream, queue = stream_case
    identifier = await insert(db.pool, "실제 저장 경보")
    assert (await receive(queue))["id"] == identifier
    await db.pool.execute("SELECT pg_notify($1,$2)", stream._channel,
                          json.dumps({"id": identifier, "timestamp": "2000-01-01T00:00:00+00:00"}))
    assert (await receive(queue, "stream_gap"))["reason"] == "stored_event_unavailable"
    assert queue.empty()
    assert await db.pool.fetchval("SELECT title FROM events WHERE id=$1", identifier) == "실제 저장 경보"


@pytest.mark.asyncio
async def test_read_failure_marks_stream_degraded_until_actual_delivery(stream_case, db, monkeypatch):
    stream, queue = stream_case
    original = stream._deliver
    async def denied(_):
        raise OSError("Injected event read failure")
    monkeypatch.setattr(stream, "_deliver", denied)
    await insert(db.pool, "조회하지 못한 경보")
    assert (await receive(queue, "stream_gap"))["reason"] == "event_read_failed"
    assert stream.status()["status"] == "degraded"
    monkeypatch.setattr(stream, "_deliver", original)
    identifier = await insert(db.pool, "조회 가능한 경보")
    assert (await receive(queue))["id"] == identifier
    assert stream.status()["status"] == "healthy"


@pytest.mark.asyncio
async def test_single_connection_pool_is_rejected_before_listener_acquisition(db, config):
    import asyncpg
    from types import SimpleNamespace
    pg = config.section("postgresql")
    pool = await asyncpg.create_pool(host=pg["host"], port=pg["port"], database=pg["database"],
        user=pg["username"], password=pg["password"], ssl=False, min_size=1, max_size=1)
    stream = DatabaseEventStream(SimpleNamespace(pool=pool))
    try:
        with pytest.raises(ValueError, match="2개 이상"):
            await stream.start()
        assert stream._connection is None
        assert stream.status()["status"] == "unhealthy"
    finally:
        await stream.stop()
        await pool.close()


@pytest.mark.asyncio
async def test_oversized_stored_event_is_not_sent_and_requests_reload(stream_case, db):
    stream, queue = stream_case
    await db.pool.execute("INSERT INTO events(engine,severity,title,description) VALUES('port_scan','WARNING','큰 경보',$1)", 'x' * 70000)
    assert (await receive(queue, "stream_gap"))["reason"] == "event_size_limit"
    assert stream.dropped == 1 and queue.empty()
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 1
    identifier = await insert(db.pool, "다음 경보")
    assert (await receive(queue))["id"] == identifier


@pytest.mark.asyncio
async def test_repeated_notification_does_not_duplicate_live_event(stream_case, db):
    stream, queue = stream_case
    identifier = await insert(db.pool, "한 번 전달할 경보")
    event = await receive(queue)
    payload = json.dumps({"id": identifier, "timestamp": event["timestamp"]})
    await db.pool.execute("SELECT pg_notify($1,$2)", stream._channel, payload)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(queue.get(), .2)
    assert stream.status()["dropped_notifications"] == 0


@pytest.mark.asyncio
async def test_other_schema_notifications_cannot_cross_into_console(stream_case, db):
    _, queue = stream_case
    schema = "stream_other_" + uuid4().hex[:12]
    parent = await db.pool.fetchval("SELECT current_schema()")
    try:
        await db.pool.execute(f'CREATE SCHEMA "{schema}"')
        await db.pool.execute(f'CREATE TABLE "{schema}".events(LIKE events INCLUDING ALL)')
        await db.pool.execute(f'CREATE TRIGGER events_stream_notify AFTER INSERT ON "{schema}".events FOR EACH ROW EXECUTE FUNCTION "{parent}".notify_committed_event()')
        await db.pool.execute(f'INSERT INTO "{schema}".events(engine,severity,title) VALUES(\'port_scan\',\'WARNING\',\'다른 콘솔 경보\')')
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(queue.get(), .2)
        identifier = await insert(db.pool, "현재 콘솔 경보")
        event = await receive(queue)
        assert event["id"] == identifier and event["title"] == "현재 콘솔 경보"
    finally:
        await db.pool.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


@pytest.mark.asyncio
async def test_bounded_notification_overflow_requests_refresh(stream_case, db, monkeypatch):
    stream, queue = stream_case
    stream._queue = asyncio.Queue(maxsize=1)
    entered, release = asyncio.Event(), asyncio.Event()
    original = stream._deliver
    async def hold(keys):
        entered.set()
        await release.wait()
        await original(keys)
    monkeypatch.setattr(stream, "_deliver", hold)
    await insert(db.pool, "첫 경보")
    await asyncio.wait_for(entered.wait(), 5)
    try:
        await db.pool.execute("INSERT INTO events(engine,severity,title) SELECT 'port_scan','WARNING','추가 경보 '||i FROM generate_series(1,5)i")
        async with asyncio.timeout(5):
            while stream.dropped == 0:
                await asyncio.sleep(.01)
        assert stream._queue.qsize() == 1
    finally:
        release.set()
    assert (await receive(queue, "stream_gap"))["reason"] == "notification_overflow"
    assert await db.pool.fetchval("SELECT count(*) FROM events") == 6


@pytest.mark.asyncio
async def test_slow_subscriber_is_not_silently_unsubscribed():
    stream = EventStream()
    queue = stream.subscribe_ws()
    for identifier in range(101):
        stream.publish({"type": "alert", "id": identifier})
    assert queue in stream._ws_subscribers
    assert json.loads(await queue.get()) == {"type": "stream_gap", "reason": "subscriber_overflow"}
    stream.publish({"type": "alert", "id": 102})
    assert json.loads(await queue.get())["id"] == 102


@pytest.mark.asyncio
async def test_actual_listener_disconnect_reconnects_and_announces_gap(stream_case, db):
    stream, queue = stream_case
    pid = await stream._connection.fetchval("SELECT pg_backend_pid()")
    assert await db.pool.fetchval("SELECT pg_terminate_backend($1)", pid)
    assert (await receive(queue, "stream_gap"))["reason"] == "connection_lost"
    assert (await receive(queue, "stream_gap"))["reason"] == "reconnected"
    assert stream.status()["status"] == "healthy"
    identifier = await insert(db.pool, "재연결 후 경보")
    assert (await receive(queue))["id"] == identifier


@pytest.mark.asyncio
async def test_new_partition_inherits_commit_notification_trigger(db):
    # 실제 릴리스 스키마처럼 파티션 루트에 설치한 트리거가 이후 파티션에도 적용된다.
    await db.pool.execute("ALTER TABLE events RENAME TO events_old")
    await db.pool.execute("CREATE TABLE events(LIKE events_old INCLUDING DEFAULTS) PARTITION BY RANGE(timestamp)")
    await db.pool.execute("CREATE TRIGGER events_stream_notify AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION notify_committed_event()")
    await db.pool.execute("CREATE TABLE events_new_partition PARTITION OF events DEFAULT")
    stream = DatabaseEventStream(db)
    await stream.start()
    queue = stream.subscribe_ws()
    try:
        identifier = await insert(db.pool, "새 파티션 경보")
        assert (await receive(queue))["id"] == identifier
        assert await db.pool.fetchval("SELECT count(*) FROM events_new_partition") == 1
    finally:
        await stream.stop()


@pytest.mark.asyncio
async def test_actual_other_python_process_commits_alert_to_stream(stream_case, db, config):
    _, queue = stream_case
    Path(config.config_path).chmod(0o600)
    code = """
import asyncio,sys
sys.path.insert(0,sys.argv[2])
from netwatcher.utils.config import Config
from netwatcher.storage.database import Database
async def main():
 db=Database(Config.load(sys.argv[1]))
 await db.connect()
 try:
  await db.pool.execute("INSERT INTO events(engine,severity,title) VALUES('port_scan','WARNING','별도 프로세스 경보')")
 finally: await db.close()
asyncio.run(main())
"""
    env = {key: value for key, value in os.environ.items() if not key.startswith("NETWATCHER_DB_")}
    env["NETWATCHER_SKIP_DOTENV"] = "1"
    child = await asyncio.create_subprocess_exec(sys.executable, "-I", "-c", code,
        str(config.config_path), str(Path(__file__).resolve().parents[2]), env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        async with asyncio.timeout(10):
            _, stderr = await child.communicate()
        assert child.returncode == 0, stderr.decode()[-1000:]
        assert (await receive(queue))["title"] == "별도 프로세스 경보"
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()


@pytest.mark.parametrize("payload", ["{}", "[]", "x" * 257,
    '{"id":true,"timestamp":"2026-10-08T00:00:00+00:00"}',
    '{"id":1,"id":2,"timestamp":"2026-10-08T00:00:00+00:00"}',
    '{"id":1,"timestamp":"2026-10-08T00:00:00"}',
    '{"id":9223372036854775808,"timestamp":"2026-10-08T00:00:00+00:00"}'])
def test_notification_parser_rejects_invalid_or_ambiguous_keys(payload):
    with pytest.raises(ValueError):
        notification_key(payload)
