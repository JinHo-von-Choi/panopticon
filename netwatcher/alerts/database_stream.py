"""DB 커밋 알림을 실제 저장 행으로 대조해 분리 콘솔에 전달한다."""

import asyncio
from collections import OrderedDict
from datetime import datetime, timezone
import json
import logging
from asyncpg import InterfaceError

from netwatcher.alerts.stream import EventStream

logger = logging.getLogger("netwatcher.alerts.database_stream")
MAX_QUEUE = 512
MAX_BATCH = 32
MAX_EVENT_BYTES = 65536


def _closed(connection):
    if connection is None:
        return True
    try:
        return connection.is_closed()
    except InterfaceError:
        # asyncpg는 끊어진 연결의 풀 프록시를 먼저 해제할 수 있다.
        return True


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate notification field")
        result[key] = value
    return result


def notification_key(payload):
    if not isinstance(payload, str) or len(payload.encode()) > 256:
        raise ValueError("Invalid event notification")
    value = json.loads(payload, object_pairs_hook=_unique)
    if not isinstance(value, dict) or set(value) != {"id", "timestamp"}:
        raise ValueError("Invalid event notification")
    identifier = value["id"]
    if type(identifier) is not int or not 0 < identifier < 2**63:
        raise ValueError("Invalid event notification")
    timestamp = value["timestamp"]
    if not isinstance(timestamp, str):
        raise ValueError("Invalid event notification")
    parsed = datetime.fromisoformat(timestamp)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Invalid event notification")
    return identifier, parsed.astimezone(timezone.utc).isoformat()


class DatabaseEventStream(EventStream):
    """알림은 재생 로그가 아니다. 누락·재연결 시 명시적으로 재조회를 요청한다."""

    def __init__(self, db):
        super().__init__()
        self.db = db
        self._queue = asyncio.Queue(maxsize=MAX_QUEUE)
        self._connection = None
        self._channel = None
        self._task = None
        self._seen = OrderedDict()
        self._gap = None
        self._stopping = False
        self._connected = False
        self._ever_connected = False
        self._read_failed = False
        self.dropped = 0
        self.failures = 0

    def status(self):
        connected = self._connected and not _closed(self._connection)
        status = "unhealthy" if not connected else "degraded" if self._read_failed else "healthy"
        return {"status": status, "queued": self._queue.qsize(),
                "dropped_notifications": self.dropped, "failures": self.failures,
                "historical_replay": False}

    def subscribe_ws(self):
        queue = super().subscribe_ws()
        if not self._connected:
            queue.put_nowait(json.dumps({"type": "stream_gap", "reason": "not_connected"}))
        return queue

    def _notify(self, _connection, _pid, channel, payload):
        if self._stopping or channel != self._channel:
            return
        try:
            key = notification_key(payload)
            self._queue.put_nowait(key)
        except asyncio.QueueFull:
            self.dropped += 1
            self._gap = "notification_overflow"
        except (ValueError, TypeError, RecursionError):
            self.failures += 1
            self._gap = "invalid_notification"

    def _resync(self, reason):
        self.publish({"type": "stream_gap", "reason": reason})

    async def _connect(self):
        connection = None
        try:
            async with asyncio.timeout(5):
                connection = await self.db.pool.acquire()
                channel = await connection.fetchval("""SELECT 'nw_events_' || pg_catalog.md5(n.nspname)
                    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
                    WHERE c.oid='events'::regclass""")
                if not isinstance(channel, str) or len(channel) != 42 or not channel.startswith("nw_events_"):
                    raise ValueError("Event notification channel unavailable")
                self._channel = channel
                await connection.add_listener(channel, self._notify)
            self._connection = connection
            self._connected = True
            if self._ever_connected:
                self._resync("reconnected")
            self._ever_connected = True
        except BaseException:
            if connection is not None:
                await self.db.pool.release(connection, timeout=2)
            raise

    async def _disconnect(self):
        self._connected = False
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                if not _closed(connection) and self._channel:
                    async with asyncio.timeout(2):
                        await connection.remove_listener(self._channel, self._notify)
            except Exception:
                logger.warning("Event listener cleanup failed; releasing connection")
            finally:
                await self.db.pool.release(connection, timeout=2)
        while not self._queue.empty():
            self._queue.get_nowait()

    async def start(self):
        if self._task is not None and not self._task.done():
            return
        self._stopping = False
        if self.db.pool.get_max_size() < 2:
            raise ValueError("실시간 경보 전달에는 DB 연결 풀이 2개 이상 필요합니다")
        await self._connect()
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        self._stopping = True
        try:
            if self._task is not None:
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
        finally:
            self._task = None
            await self._disconnect()

    async def _deliver(self, keys):
        # 최대 ID를 따라가지 않고 커밋 알림이 가리키는 저장 행을 대조한다.
        async with asyncio.timeout(2):
            rows = await self.db.pool.fetch("""SELECT CASE
                WHEN octet_length(pg_catalog.row_to_json(e)::text)>$3 THEN NULL
                ELSE pg_catalog.row_to_json(e)::jsonb END AS event FROM
                unnest($1::bigint[],$2::timestamptz[]) WITH ORDINALITY AS i(id,timestamp,position)
                JOIN events e ON e.id=i.id AND e.timestamp=i.timestamp ORDER BY i.position""",
                [key[0] for key in keys], [key[1] for key in keys], MAX_EVENT_BYTES)
        if len(rows) != len(keys):
            self._gap = "stored_event_unavailable"
        for stored in rows:
            row = stored["event"]
            if row is None:
                self.dropped += 1
                self._gap = "event_size_limit"
                continue
            key = (row["id"], datetime.fromisoformat(row["timestamp"]).astimezone(timezone.utc).isoformat())
            if key in self._seen:
                continue
            event = {**dict(row), "type": "alert"}
            if len(json.dumps(event, ensure_ascii=False).encode()) > MAX_EVENT_BYTES:
                self.dropped += 1
                self._gap = "event_size_limit"
                continue
            self.publish(event)
            self._seen[key] = None
            if len(self._seen) > 2048:
                self._seen.popitem(last=False)

    async def _run(self):
        while not self._stopping:
            if _closed(self._connection):
                self.failures += 1
                self._resync("connection_lost")
                await self._disconnect()
                try:
                    await self._connect()
                except Exception:
                    logger.warning("Event stream reconnect failed")
                    await asyncio.sleep(1)
                    continue
            if self._gap:
                self._resync(self._gap)
                self._gap = None
            try:
                async with asyncio.timeout(1):
                    first = await self._queue.get()
            except TimeoutError:
                continue
            keys = [first]
            while len(keys) < MAX_BATCH and not self._queue.empty():
                keys.append(self._queue.get_nowait())
            try:
                await self._deliver(keys)
                self._read_failed = False
            except Exception:
                self._read_failed = True
                self.failures += 1
                self._resync("event_read_failed")
                logger.warning("Committed event read failed; console refresh required")
