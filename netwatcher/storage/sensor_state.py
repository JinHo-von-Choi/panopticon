"""DB 시각과 실행 소유권으로 분리 센서의 관측 상태를 공유한다."""

from copy import deepcopy
import asyncio
import json
import time
from uuid import UUID

MAX_SENSORS = 128
MAX_SNAPSHOT_BYTES = 60000


class SensorLeaseLost(RuntimeError):
    """실행 소유권이 없거나 DB에서 확인할 수 있는 임대 기간이 끝났다."""


def _identity(sensor_id, owner):
    if (not isinstance(sensor_id, str) or not 1 <= len(sensor_id) <= 128
            or any(ord(char) < 32 or ord(char) == 127 for char in sensor_id)):
        raise ValueError("센서 식별자가 유효하지 않습니다")
    return UUID(str(owner))


def _lease(seconds):
    if type(seconds) is not int or not 10 <= seconds <= 120:
        raise ValueError("센서 실행 소유권 유효기간은 10~120초여야 합니다")


def _snapshot(value):
    if not isinstance(value, dict):
        raise ValueError("센서 관측 상태는 객체여야 합니다")
    try:
        payload = json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("센서 관측 상태를 저장할 수 없습니다") from None
    if len(payload.encode()) > MAX_SNAPSHOT_BYTES:
        raise ValueError("센서 관측 상태의 저장 한도를 초과했습니다")
    return json.loads(payload)


class SensorStateRepository:
    def __init__(self, db):
        self.db = db

    async def claim(self, sensor_id, owner, *, lease_seconds=30):
        token = _identity(sensor_id, owner)
        _lease(lease_seconds)
        async with self.db.pool.acquire() as conn, conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(178903421,3)")
            row = await conn.fetchrow("SELECT * FROM sensor_runtime_state WHERE sensor_id=$1 FOR UPDATE", sensor_id)
            if row is None and await conn.fetchval("SELECT count(*) FROM sensor_runtime_state") >= MAX_SENSORS:
                raise ValueError("센서 상태 등록 한도를 초과했습니다")
            claimed = await conn.fetchval("""INSERT INTO sensor_runtime_state
                (sensor_id,owner,lease_expires_at) VALUES($1,$2,clock_timestamp()+$3*INTERVAL '1 second')
                ON CONFLICT(sensor_id) DO UPDATE SET owner=EXCLUDED.owner,
                    started_at=clock_timestamp(),heartbeat_at=clock_timestamp(),
                    lease_expires_at=EXCLUDED.lease_expires_at,stopped=FALSE,snapshot='{}'
                WHERE sensor_runtime_state.stopped OR sensor_runtime_state.lease_expires_at <= clock_timestamp()
                RETURNING owner""", sensor_id, token, lease_seconds)
            if claimed != token:
                raise SensorLeaseLost("다른 실행이 센서를 사용하고 있습니다")

    async def publish(self, sensor_id, owner, snapshot, *, lease_seconds=30):
        token = _identity(sensor_id, owner)
        _lease(lease_seconds)
        snapshot = _snapshot(snapshot)
        changed = await self.db.pool.fetchval("""UPDATE sensor_runtime_state SET snapshot=$3,
            heartbeat_at=clock_timestamp(),lease_expires_at=clock_timestamp()+$4*INTERVAL '1 second'
            WHERE sensor_id=$1 AND owner=$2 AND NOT stopped AND lease_expires_at>clock_timestamp()
            RETURNING owner""", sensor_id, token, snapshot, lease_seconds)
        if changed != token:
            raise SensorLeaseLost("센서 실행 소유권이 만료되거나 변경되었습니다")

    async def release(self, sensor_id, owner):
        token = _identity(sensor_id, owner)
        return bool(await self.db.pool.fetchval("""UPDATE sensor_runtime_state SET stopped=TRUE,
            lease_expires_at=clock_timestamp() WHERE sensor_id=$1 AND owner=$2 RETURNING TRUE""", sensor_id, token))

    async def read(self, sensor_id):
        _identity(sensor_id, UUID(int=0))
        row = await self.db.pool.fetchrow("""SELECT sensor_id,owner,started_at,heartbeat_at,snapshot,
            stopped OR lease_expires_at<=clock_timestamp() AS stale,
            GREATEST(0,EXTRACT(EPOCH FROM lease_expires_at-clock_timestamp())) AS lease_remaining_seconds,
            GREATEST(0,EXTRACT(EPOCH FROM clock_timestamp()-heartbeat_at)) AS heartbeat_age_seconds
            FROM sensor_runtime_state WHERE sensor_id=$1""", sensor_id)
        return None if row is None else {**dict(row), "heartbeat_age_seconds": float(row["heartbeat_age_seconds"]),
            "lease_remaining_seconds": float(row["lease_remaining_seconds"])}


class StoredSensorObservation:
    """동기 snapshot API를 유지하면서 DB 조회 실패와 캐시 만료를 드러낸다."""

    def __init__(self, repository, sensor_id, *, cache_seconds=10):
        _identity(sensor_id, UUID(int=0))
        if not isinstance(cache_seconds, (int, float)) or isinstance(cache_seconds, bool) or not 1 <= cache_seconds <= 30:
            raise ValueError("센서 관측 캐시 유효기간이 유효하지 않습니다")
        self.repository, self.sensor_id = repository, sensor_id
        self.cache_seconds = cache_seconds
        self._row = None
        self._read_at = None
        self._failed = False
        self._refresh_lock = asyncio.Lock()
        self._refresh_epoch = 0

    async def refresh(self):
        async with self._refresh_lock:
            started = time.monotonic()
            epoch = self._refresh_epoch
            try:
                row = await self.repository.read(self.sensor_id)
            except BaseException:
                # 진행 중인 조회의 취소도 최신 상태를 확인하지 못한 경우다.
                self._failed = True
                raise
            if epoch == self._refresh_epoch:
                self._row = row
                self._read_at = started
                self._failed = False

    def invalidate(self):
        """읽기 서비스가 중지되면 이전 관측을 현재 상태로 쓰지 않는다."""
        self._failed = True
        self._refresh_epoch += 1

    def snapshot(self):
        row = self._row
        stale = (self._failed or row is None or row["stale"] or self._read_at is None
                 or time.monotonic() - self._read_at >= min(self.cache_seconds, row["lease_remaining_seconds"]))
        result = deepcopy(row["snapshot"]) if row else {}
        result.update({"sensor_id": self.sensor_id, "input_mode": "native", "execution_process": "separate"})
        if stale:
            result["state"] = "stale" if row else "unknown"
            result["no_traffic_observed"] = None
            result["reasons"] = [*(result.get("reasons") or []), "센서의 최신 관측 상태를 확인할 수 없습니다."]
        # 살아 있는 프로세스의 heartbeat도 빈 snapshot을 건강한 관측으로 바꾸지 않는다.
        elif "state" not in result:
            result["state"] = "unknown"
            result["no_traffic_observed"] = None
            result["reasons"] = ["센서의 관측 근거를 아직 받지 못했습니다."]
        result.setdefault("reasons", [])
        result.setdefault("no_traffic_observed", None)
        result["sensor_heartbeat"] = {"confirmed": not stale,
            "age_seconds": row["heartbeat_age_seconds"] + time.monotonic() - self._read_at if row and self._read_at is not None else None}
        return result
