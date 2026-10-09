"""원래 경보를 바꾸지 않고, 단일 사건에 한정된 업무 판정을 기록한다."""

from datetime import datetime, timedelta, timezone
import uuid

from netwatcher.inventory.context import asset_context

NORMAL_DECISIONS = frozenset({"expected_backup", "approved_maintenance"})


class ReviewConflict(ValueError):
    pass


def event_scope(event):
    external = (event.get("metadata") or {}).get("external_eve") or {}
    return {"source_ip": str(event.get("source_ip") or ""),
            "source_mac": str(event.get("source_mac") or "").lower(),
            "dest_ip": str(event.get("dest_ip") or ""),
            "dest_mac": str(event.get("dest_mac") or "").lower(),
            "flow_id": external.get("flow_id"),
            "observed_at": str(event.get("timestamp") or ""),
            "sensor_id": external.get("sensor_id"), "source_id": external.get("source_id"),
            "src_port": external.get("src_port"), "dest_port": external.get("dest_port"),
            "protocol": external.get("proto"),
            "signature_id": (external.get("details") or {}).get("signature_id")}


class BusinessReviews:
    def __init__(self, db):
        self.db = db

    async def raw(self, event_id, *, connection=None):
        row = await (connection if connection is not None else self.db.pool).fetchrow("SELECT * FROM business_reviews WHERE event_id=$1", event_id)
        if row is None:
            return None
        result = dict(row)
        for key in ("reviewed_at", "expires_at"):
            if result[key] is not None:
                value = result[key] if isinstance(result[key], datetime) else datetime.fromisoformat(str(result[key]))
                result[key] = value.astimezone(timezone.utc).isoformat()
        return result

    async def history(self, event_id, before_version=None):
        async with self.db.pool.acquire() as conn, conn.transaction(isolation="repeatable_read", readonly=True):
            if not await conn.fetchval("SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)", event_id):
                raise ReviewConflict("event_missing")
            rows = await conn.fetch("""SELECT * FROM business_review_history WHERE event_id=$1
                AND ($2::bigint IS NULL OR version<$2) ORDER BY version DESC LIMIT 51""",
                event_id, before_version)
        history = []
        for row in rows[:50]:
            record = dict(row)
            for key in ("reviewed_at", "expires_at"):
                if record[key] is not None:
                    value = record[key] if isinstance(record[key], datetime) else datetime.fromisoformat(str(record[key]))
                    record[key] = value.astimezone(timezone.utc).isoformat()
            history.append(record)
        return {"history": history, "next_before_version": rows[49]["version"] if len(rows)>50 else None}

    async def _identity(self, conn, event, now):
        if not event.get("source_ip") or not event.get("source_mac"):
            return None
        rows = await conn.fetch("SELECT * FROM devices WHERE ip_address=$1::inet", str(event["source_ip"]))
        if len(rows) != 1 or str(rows[0]["mac_address"]).lower() != str(event["source_mac"]).lower():
            return None
        device = dict(rows[0])
        if asset_context(device, now=now)["status"] != "confirmed":
            return None
        return device

    async def _flow(self, conn, event):
        scope = event_scope(event)
        original = ((event.get("metadata") or {}).get("external_eve") or {}).get("original_ref") or {}
        rows = await conn.fetch("""SELECT ingest_id,record,observed_at FROM eve_records
            WHERE sensor_id=$1 AND source_id=$2 AND record->>'flow_id'=$3 AND event_type='flow'
              AND record->>'src_ip'=$4 AND record->>'dest_ip'=$5
              AND record->>'proto'=$6 AND record->>'src_port'=$7 AND record->>'dest_port'=$8
              AND ((record->'details'->>'start' IS NOT NULL AND record->'details'->>'end' IS NOT NULL
                    AND $10::timestamptz BETWEEN (record->'details'->>'start')::timestamptz
                                           AND (record->'details'->>'end')::timestamptz)
                   OR (record->'details'->>'start' IS NULL AND record->'details'->>'end' IS NULL
                       AND record->'original_ref'->>'generation'=$9
                       AND observed_at BETWEEN $10::timestamptz-interval '5 minutes'
                                           AND $10::timestamptz+interval '5 minutes'))
            ORDER BY observed_at DESC,ingest_id DESC LIMIT 65""",
            scope["sensor_id"], scope["source_id"], scope["flow_id"], scope["source_ip"],
            scope["dest_ip"], scope["protocol"], str(scope["src_port"]), str(scope["dest_port"]),
            original.get("generation"), event["timestamp"])
        if not rows:
            return None
        if len(rows) > 64:
            raise ReviewConflict("flow_evidence_ambiguous")
        anchors = {self._anchor(row["record"]) for row in rows}
        if len(anchors) != 1:
            raise ReviewConflict("flow_evidence_ambiguous")
        previous = None
        previous_at = None
        observed_macs = {"src": set(), "dest": set()}
        for row in reversed(rows):
            record = row["record"]
            counters = self._counters(record)
            if counters is None:
                raise ReviewConflict("flow_evidence_incomplete")
            if previous is not None:
                if row["observed_at"] == previous_at and counters != previous:
                    raise ReviewConflict("flow_evidence_ambiguous")
                if any(current < old for current, old in zip(counters, previous)):
                    raise ReviewConflict("flow_counter_reset")
            previous, previous_at = counters, row["observed_at"]
            for key, address in (("src", scope["source_mac"]), ("dest", scope["dest_mac"])):
                macs = set(record.get(key + "_macs") or [])
                if record.get(key + "_mac"):
                    macs.add(record[key + "_mac"])
                observed_macs[key].update(macs)
                if len(observed_macs[key]) > 1 or (address and macs and address not in macs):
                    raise ReviewConflict("flow_evidence_ambiguous")
        return rows[0]

    @staticmethod
    def _anchor(record):
        details = record.get("details") or {}
        if details.get("start") and details.get("end"):
            return "time:" + details["start"]
        return "file:" + record["original_ref"]["generation"]

    @staticmethod
    def _counters(record):
        details = record.get("details") or {}
        values = tuple(details.get(key) for key in ("bytes_toserver", "bytes_toclient"))
        if any(type(value) is not int or value < 0 for value in values):
            return None
        return values

    @staticmethod
    def _bytes(record):
        details = record.get("details") or {}
        values = [details.get(key) for key in ("bytes_toserver", "bytes_toclient")]
        if any(type(value) is not int or value < 0 for value in values):
            return None
        return sum(values) or None

    async def get(self, event_id, *, connection=None, now=None):
        if connection is not None:
            return await self._get(connection, event_id, now or datetime.now(timezone.utc))
        async with self.db.pool.acquire() as conn, conn.transaction(isolation="repeatable_read", readonly=True):
            snapshot = await conn.fetchval("SELECT transaction_timestamp()")
            snapshot = snapshot if isinstance(snapshot, datetime) else datetime.fromisoformat(snapshot)
            return await self._get(conn, event_id, now or snapshot)

    async def _get(self, conn, event_id, now):
        review = await self.raw(event_id, connection=conn)
        if review is None:
            if not await conn.fetchval("SELECT EXISTS(SELECT 1 FROM events WHERE id=$1)", event_id):
                raise ReviewConflict("event_missing")
            return {"state": "unreviewed", "reason": "no_review", "review": None}
        if review["decision"] not in NORMAL_DECISIONS:
            return {"state": review["decision"], "reason": "operator_decision", "review": review}
        def reopen(reason):
            return {"state": "needs_review", "reason": reason, "review": review}
        if not review["expires_at"] or datetime.fromisoformat(review["expires_at"]) <= now:
            return reopen("expired")
        event = await conn.fetchrow("SELECT * FROM events WHERE id=$1", event_id)
        if event is None:
            return reopen("event_missing")
        scope = event_scope(dict(event))
        if any(scope[key] != review["scope"].get(key) for key in scope):
            return reopen("communication_changed")
        flow_id = review["scope"].get("flow_evidence_id")
        evidence = await conn.fetchval("SELECT record FROM eve_records WHERE ingest_id=$1", uuid.UUID(flow_id)) if flow_id else None
        if evidence is None:
            return reopen("flow_evidence_missing")
        try:
            latest = await self._flow(conn, event)
        except ReviewConflict as error:
            return reopen(str(error))
        if latest is None:
            return reopen("flow_evidence_missing")
        latest_bytes = self._bytes(latest["record"])
        if latest_bytes is None:
            return reopen("flow_evidence_incomplete")
        if latest_bytes > review["scope"].get("max_bytes", 0):
            return reopen("volume_exceeded")
        evidence_counters = self._counters(evidence)
        if evidence_counters is None:
            return reopen("flow_evidence_incomplete")
        if (self._anchor(latest["record"]) != self._anchor(evidence) or
                any(new < old for new, old in zip(self._counters(latest["record"]), evidence_counters))):
            return reopen("flow_counter_reset")
        if (self._bytes(evidence) != review["scope"].get("flow_bytes") or
                evidence.get("original_ref", {}).get("sha256") != review["scope"].get("flow_hash")):
            return reopen("flow_evidence_changed")
        work = review["scope"].get("work_schedule")
        if work:
            from netwatcher.investigation.schedules import matches
            job = await conn.fetchrow("""SELECT w.*,l.version AS link_version FROM event_work_links l
                JOIN work_schedules w ON w.id=l.schedule_id WHERE l.event_id=$1""", event_id)
            if job is None or str(job["id"]) != work["id"] or job["link_version"] != work["link_version"]:
                return reopen("work_link_changed")
            if job["revoked_at"]:
                return reopen("work_cancelled")
            if job["version"] != work["version"] or job["content"] != work["content"] or not matches(job,event):
                return reopen("work_scope_invalid")
        device = await self._identity(conn, event, now)
        if (device is None or device["context_version"] != review["scope"].get("context_version")
                or device["ip_mapping_version"] != review["scope"].get("mapping_version")):
            return reopen("ownership_changed")
        return {"state": "normal_confirmed", "reason": review["decision"], "review": review}

    async def save(self, event_id, body, actor):
        now = datetime.now(timezone.utc)
        async with self.db.pool.acquire() as conn, conn.transaction():
            event = await conn.fetchrow("SELECT * FROM events WHERE id=$1 FOR UPDATE", event_id)
            if event is None:
                raise ReviewConflict("event_missing")
            await conn.execute("""INSERT INTO business_review_history
                SELECT event_id,version,decision,note,actor,scope,reviewed_at,expires_at
                FROM business_reviews WHERE event_id=$1 ON CONFLICT DO NOTHING""", event_id)
            if await conn.fetchval("SELECT count(*) FROM business_review_history WHERE event_id=$1", event_id) >= 1000:
                raise ReviewConflict("history_capacity")
            scope = event_scope(dict(event))
            expiry = None
            if body.decision in NORMAL_DECISIONS:
                device = await self._identity(conn, event, now)
                if device is None:
                    raise ReviewConflict("ownership_unconfirmed")
                if (not scope["dest_ip"] or not scope["sensor_id"] or not scope["source_id"]
                        or scope["protocol"] not in ("TCP", "UDP") or not scope["dest_port"]):
                    raise ReviewConflict("communication_incomplete")
                flow = await self._flow(conn, event)
                volume = self._bytes(flow["record"]) if flow else None
                if volume is None or body.max_bytes is None:
                    raise ReviewConflict("flow_evidence_incomplete")
                if volume > body.max_bytes:
                    raise ReviewConflict("volume_exceeded")
                scope.update(flow_evidence_id=str(flow["ingest_id"]), flow_bytes=volume,
                             flow_hash=flow["record"]["original_ref"]["sha256"], max_bytes=body.max_bytes)
                scope.update(context_version=device["context_version"], mapping_version=device["ip_mapping_version"])
                from netwatcher.investigation.schedules import matches, serialize
                job = await conn.fetchrow("""SELECT w.*,l.version AS link_version FROM event_work_links l
                    JOIN work_schedules w ON w.id=l.schedule_id WHERE l.event_id=$1 FOR SHARE OF w""", event_id)
                if job:
                    if job["revoked_at"] or not matches(job,event):
                        raise ReviewConflict("work_scope_invalid")
                    if body.max_bytes > job["content"]["max_flow_bytes"]:
                        raise ReviewConflict("work_volume_limit")
                    record = serialize(job)
                    scope["work_schedule"] = {key: record[key] for key in
                                              ("id", "version", "link_version", "content", "actor", "created_at")}
                scope["asset_context"] = {key: device["context_profile"].get(key) for key in
                                          ("role", "confirmed_by", "confirmed_at", "expires_at")}
                expiry = min(now + timedelta(hours=body.valid_hours),
                             datetime.fromisoformat(device["context_profile"]["expires_at"]))
            row = await conn.fetchrow("""INSERT INTO business_reviews
                (event_id,version,decision,note,actor,scope,reviewed_at,expires_at)
                SELECT $1,1,$3,$4,$5,$6,$7,$8 WHERE $2=0 OR EXISTS
                    (SELECT 1 FROM business_reviews WHERE event_id=$1)
                ON CONFLICT(event_id) DO UPDATE SET version=business_reviews.version+1,
                    decision=EXCLUDED.decision,note=EXCLUDED.note,actor=EXCLUDED.actor,
                    scope=EXCLUDED.scope,reviewed_at=EXCLUDED.reviewed_at,expires_at=EXCLUDED.expires_at
                WHERE business_reviews.version=$2 RETURNING version""",
                event_id, body.expected_version, body.decision, body.note, actor[:255], scope, now, expiry)
            if row is None:
                raise ReviewConflict("version_changed")
            await conn.execute("""INSERT INTO business_review_history
                SELECT event_id,version,decision,note,actor,scope,reviewed_at,expires_at
                FROM business_reviews WHERE event_id=$1""", event_id)
        return await self.get(event_id)
