"""EVE 기록·경보·읽기 위치를 한 트랜잭션으로 저장한다."""

import json
import uuid

from netwatcher.ingest.assets import parse_networks, record_assets
from netwatcher.storage.repositories import EventRepository


class StaleCheckpointError(RuntimeError):
    """다른 수집기가 체크포인트를 먼저 갱신했다."""


class EveCapacityError(RuntimeError):
    """보존 정책의 한도에 도달해 수집을 일시 중지했다."""


class EveRepository:
    def __init__(self, db, event_stream=None, *, max_records=250000, max_bytes=268435456, local_networks=None,
                 feeds=None):
        if (isinstance(max_records, bool) or not isinstance(max_records, int) or not 1 <= max_records <= 10000000 or
                isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1024 <= max_bytes <= 64 * 1024**3):
            raise ValueError("Invalid EVE storage budget")
        self._db = db
        self._events = EventRepository(db)
        self._event_stream = event_stream
        self.max_records, self.max_bytes = max_records, max_bytes
        self.local_networks = parse_networks(local_networks)
        # 수집기가 디코딩할 때 대조한다. 저장소는 피드를 갖고만 있다.
        self.feeds = feeds

    async def load(self, sensor_id, source_id):
        row = await self._db.pool.fetchrow(
            "SELECT revision, state FROM eve_checkpoints WHERE sensor_id=$1 AND source_id=$2",
            sensor_id, source_id,
        )
        return (row["revision"], row["state"]) if row else (None, None)

    async def commit(self, sensor_id, source_id, revision, state, records):
        published = []
        prepared = self._prepare_records(records)
        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                current = await conn.fetchval("""SELECT revision FROM eve_checkpoints
                    WHERE sensor_id=$1 AND source_id=$2 FOR UPDATE""", sensor_id, source_id)
                if current != revision:
                    raise StaleCheckpointError("EVE checkpoint was changed by another collector")
                usage = await conn.fetchrow("""SELECT record_count,accounted_bytes FROM eve_storage_usage
                    WHERE sensor_id=$1 AND source_id=$2 FOR UPDATE""", sensor_id, source_id)
                count, total = (usage["record_count"], usage["accounted_bytes"]) if usage else (0, 0)
                await self._check_capacity(conn, prepared, count, total)
                if revision is None:
                    claimed = await conn.fetchval(
                        """INSERT INTO eve_checkpoints(sensor_id,source_id,state)
                           VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING revision""",
                        sensor_id, source_id, state,
                    )
                else:
                    claimed = await conn.fetchval(
                        """UPDATE eve_checkpoints SET revision=revision+1,state=$4,updated_at=NOW()
                           WHERE sensor_id=$1 AND source_id=$2 AND revision=$3 RETURNING revision""",
                        sensor_id, source_id, revision, state,
                    )
                if claimed is None:
                    raise StaleCheckpointError("EVE checkpoint was changed by another collector")
                await conn.execute("""INSERT INTO eve_storage_usage(sensor_id,source_id)
                                   VALUES($1,$2) ON CONFLICT DO NOTHING""", sensor_id, source_id)
                alert_ids = [identity for identity, record in prepared[0].items()
                             if record["event_type"] == "alert" and record.get("supported")]
                reserved = await conn.fetch("""SELECT ingest_id,
                    nextval(pg_get_serial_sequence('events','id')) AS event_id
                    FROM unnest($1::uuid[]) AS candidate(ingest_id)""", alert_ids) if alert_ids else []
                event_ids = {row["ingest_id"]: row["event_id"] for row in reserved}
                inserted, charge = await self._insert_records(
                    conn, sensor_id, source_id, records, prepared=prepared, event_ids=event_ids)
                count += len(inserted)
                total += charge
                if count > self.max_records or total > self.max_bytes:
                    raise EveCapacityError("EVE retained data budget exceeded")
                published = await self._project_records(conn, inserted, event_ids=event_ids)
                # 새로 저장된 기록만 센다. 같은 범위를 다시 읽어도 건수가 늘지 않는다.
                await record_assets(conn, sensor_id, source_id, inserted, self.local_networks)
                await conn.execute("""UPDATE eve_storage_usage SET record_count=$3,accounted_bytes=$4
                                   WHERE sensor_id=$1 AND source_id=$2""", sensor_id, source_id, count, total)
        if self._event_stream is not None:
            for event in published:
                self._event_stream.publish(event)
        return claimed

    def _prepare_records(self, records):
        unique = {}
        for record in records:
            identity = uuid.UUID(record["ingest_id"])
            if identity in unique:
                if unique[identity]["original_ref"]["sha256"] != record["original_ref"]["sha256"]:
                    raise ValueError("EVE identity refers to different source content")
                continue
            unique[identity] = record
        payload = []
        for identity, record in unique.items():
            projected = record["event_type"] == "alert" and record.get("supported")
            charge = len(json.dumps(record, ensure_ascii=False, allow_nan=False).encode()) * (2 if projected else 1) + 1024
            payload.append({"ingest_id": str(identity), "event_type": record["event_type"],
                "observed_at": record.get("observed_at"), "record": record,
                "received_at": record.get("received_at"), "accounted_bytes": charge})
        return unique, payload

    async def _check_capacity(self, conn, prepared, count, total):
        unique, payload = prepared
        if (count + len(payload) <= self.max_records
                and total + sum(row["accounted_bytes"] for row in payload) <= self.max_bytes):
            return
        # 상한에 가까운 배치만 중복을 먼저 대조한다. 거절할 입력을 삽입한 뒤
        # 롤백하면 반복 재시도마다 데이터·인덱스 WAL을 불필요하게 기록한다.
        existing = await conn.fetch("""SELECT ingest_id,record->'original_ref'->>'sha256' AS source_hash
            FROM eve_records WHERE ingest_id=ANY($1::uuid[])""", list(unique))
        hashes = {row["ingest_id"]: row["source_hash"] for row in existing}
        if any(hashes[identity] != unique[identity]["original_ref"]["sha256"] for identity in hashes):
            raise ValueError("EVE identity refers to different source content")
        fresh = [row for row in payload if uuid.UUID(row["ingest_id"]) not in hashes]
        if (count + len(fresh) > self.max_records
                or total + sum(row["accounted_bytes"] for row in fresh) > self.max_bytes):
            raise EveCapacityError("EVE retained data budget exceeded")

    async def _insert_records(self, conn, sensor_id, source_id, records, *, prepared=None, event_ids=None):
        unique, payload = prepared if prepared is not None else self._prepare_records(records)
        if not unique:
            return [], 0
        payload = [{**row, "event_id": (event_ids or {}).get(uuid.UUID(row["ingest_id"]))} for row in payload]
        rows = await conn.fetch("""INSERT INTO eve_records
            (ingest_id,sensor_id,source_id,event_type,observed_at,record,received_at,accounted_bytes,event_id)
            SELECT r.ingest_id,$1,$2,r.event_type,r.observed_at,r.record,
                   COALESCE(r.received_at,NOW()),r.accounted_bytes,r.event_id
            FROM jsonb_to_recordset($3::jsonb) AS r(ingest_id uuid,event_type text,
                observed_at timestamptz,record jsonb,received_at timestamptz,accounted_bytes bigint,event_id bigint)
            ON CONFLICT DO NOTHING RETURNING ingest_id,accounted_bytes""", sensor_id, source_id, payload)
        inserted = {row["ingest_id"] for row in rows}
        conflicts = list(unique.keys() - inserted)
        if conflicts:
            existing = await conn.fetch("""SELECT ingest_id,record->'original_ref'->>'sha256' AS source_hash
                FROM eve_records WHERE ingest_id=ANY($1::uuid[])""", conflicts)
            hashes = {row["ingest_id"]: row["source_hash"] for row in existing}
            if any(hashes.get(identity) != unique[identity]["original_ref"]["sha256"] for identity in conflicts):
                raise ValueError("EVE identity refers to different source content")
        return [record for identity, record in unique.items() if identity in inserted], sum(row["accounted_bytes"] for row in rows)

    async def _project_records(self, conn, records, *, event_ids):
        events = []
        for record in records:
            if record["event_type"] != "alert" or not record.get("supported"):
                continue
            detail = record["details"]
            events.append({"ingest_id": record["ingest_id"], "engine": "suricata",
                "severity": {1: "CRITICAL", 2: "WARNING", 3: "INFO"}.get(detail["severity"], "INFO"),
                "title": detail.get("signature") or f"Suricata #{detail['signature_id']}",
                "timestamp": record["observed_at"], "source_ip": record.get("src_ip"),
                "dest_ip": record.get("dest_ip"), "source_mac": record.get("src_mac"),
                "dest_mac": record.get("dest_mac"), "metadata": {"external_eve": record}})
        reserved = {uuid.UUID(event["ingest_id"]): event_ids[uuid.UUID(event["ingest_id"])]
                    for event in events}
        saved = await self._events.insert_batch_mapped(events, connection=conn, event_ids=reserved)
        if saved != reserved:
            raise ValueError("EVE event identity differs from its reserved link")
        return [{"type": "alert", "id": saved[uuid.UUID(event["ingest_id"])],
                 **{key: event[key] for key in ("engine", "severity", "title", "timestamp",
                     "source_ip", "dest_ip", "source_mac", "dest_mac")}} for event in events]

    async def storage_status(self, sensor_id, source_id):
        row = await self._db.pool.fetchrow("""SELECT record_count,accounted_bytes FROM eve_storage_usage
                                          WHERE sensor_id=$1 AND source_id=$2""", sensor_id, source_id)
        return {"records": row["record_count"] if row else 0, "accounted_bytes": row["accounted_bytes"] if row else 0,
                "max_records": self.max_records, "max_bytes": self.max_bytes,
                "measurement": "logical_retained_content_budget", "physical_disk_bytes": None}

    async def prune(self, sensor_id, source_id, *, days=30, limit=1000):
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= 3650 or not 1 <= limit <= 1000:
            raise ValueError("Invalid EVE retention policy")
        async with self._db.pool.acquire() as conn:
            async with conn.transaction():
                usage = await conn.fetchrow("""SELECT record_count,accounted_bytes FROM eve_storage_usage
                                            WHERE sensor_id=$1 AND source_id=$2 FOR UPDATE""", sensor_id, source_id)
                if usage is None:
                    return 0
                rows = await conn.fetch("""SELECT ingest_id,event_id,accounted_bytes FROM eve_records
                    WHERE sensor_id=$1 AND source_id=$2 AND received_at < NOW()-make_interval(days=>$3)
                    ORDER BY received_at LIMIT $4 FOR UPDATE""", sensor_id, source_id, days, limit)
                if not rows:
                    return 0
                ids = [row["ingest_id"] for row in rows]
                event_ids = [row["event_id"] for row in rows if row["event_id"] is not None]
                await conn.execute("DELETE FROM events WHERE id=ANY($1::bigint[])", event_ids)
                await conn.execute("DELETE FROM event_ingest WHERE ingest_id=ANY($1::uuid[])", ids)
                await conn.execute("DELETE FROM event_work_links WHERE event_id=ANY($1::bigint[])", event_ids)
                await conn.execute("DELETE FROM case_workflows WHERE event_id=ANY($1::bigint[])", event_ids)
                await conn.execute("DELETE FROM business_reviews WHERE event_id=ANY($1::bigint[])", event_ids)
                await conn.execute("DELETE FROM eve_records WHERE ingest_id=ANY($1::uuid[])", ids)
                await conn.execute("""UPDATE eve_storage_usage SET record_count=record_count-$3,
                    accounted_bytes=accounted_bytes-$4 WHERE sensor_id=$1 AND source_id=$2""",
                    sensor_id, source_id, len(rows), sum(row["accounted_bytes"] for row in rows))
                return len(rows)
