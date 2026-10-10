"""Persistent single-console enrollment and signed host telemetry gateway."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from uuid import UUID, uuid4, uuid5

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field


# 에이전트 이상 이벤트를 경보로 옮길 때 쓰는 ingest_id 이름공간. 바꾸면 재전송이 중복 경보가 된다.
AGENT_ALERT_NAMESPACE = UUID("6f0d7c55-3a8e-4f63-9a51-2b7f0f6c1d42")


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Enrollment(StrictBody):
    enrollment_token: str = Field(min_length=1, max_length=512)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=128)


class Resources(StrictBody):
    load_1: float = Field(ge=0)
    memory_total_bytes: int = Field(ge=0, strict=True)
    memory_available_bytes: int = Field(ge=0, strict=True)
    agent_rss_bytes: int = Field(ge=0, strict=True)


class Heartbeat(StrictBody):
    agent_uuid: UUID
    latency_ms: float = Field(ge=0, le=3600000)
    resources: Resources


class ConnectionEvent(StrictBody):
    kind: str = Field(pattern=r"^(connection|anomaly)$")
    local_address: str = Field(min_length=1, max_length=128)
    remote_address: str = Field(min_length=1, max_length=128)
    state: str = Field(min_length=1, max_length=32)
    inode: int = Field(ge=0, strict=True)
    observed_at: int = Field(ge=0, strict=True)
    detail: str = Field(default="", max_length=1024)


class Events(StrictBody):
    agent_uuid: UUID
    seq: int = Field(ge=1, le=9223372036854775807, strict=True)
    events: list[ConnectionEvent] = Field(min_length=1, max_length=256)


class AgentGatewayStore:
    """SQLite transactions enforce single-use enrollment and sequence identity."""

    def __init__(self, database: str, enrollment_token: str | None = None):
        self.database = str(database)
        self.enrollment_token = enrollment_token if enrollment_token is not None else os.getenv("PANOPTICON_ENROLLMENT_TOKEN", "")
        if self.enrollment_token:
            digest = hashlib.sha256(self.enrollment_token.encode()).hexdigest()
            with self.connect() as db, db:
                db.execute("INSERT OR IGNORE INTO enrollment_tokens(digest, expires_at) VALUES (?, ?)",
                           (digest, time.time() + 900))

    @contextmanager
    def connect(self):
        path = Path(self.database)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        db = sqlite3.connect(path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS enrollment_tokens (
                    digest TEXT PRIMARY KEY, expires_at REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS agents (
                    agent_uuid TEXT PRIMARY KEY, token_hash TEXT NOT NULL, signing_key TEXT NOT NULL,
                    hostname TEXT NOT NULL, platform TEXT NOT NULL, enrolled_at REAL NOT NULL,
                    last_seen REAL, latency_ms REAL, resources TEXT
                );
                CREATE TABLE IF NOT EXISTS agent_events (
                    agent_uuid TEXT NOT NULL REFERENCES agents(agent_uuid), seq INTEGER NOT NULL,
                    digest TEXT NOT NULL, payload TEXT NOT NULL, received_at REAL NOT NULL,
                    PRIMARY KEY (agent_uuid, seq)
                );
            """)
            db.execute("PRAGMA foreign_keys=ON")
            yield db
        finally:
            db.close()

    def enroll(self, body: Enrollment):
        if not self.enrollment_token:
            raise HTTPException(503, "Agent enrollment is not configured")
        if not hmac.compare_digest(body.enrollment_token.encode(), self.enrollment_token.encode()):
            raise HTTPException(401, "Invalid enrollment token")
        now = time.time()
        digest = hashlib.sha256(self.enrollment_token.encode()).hexdigest()
        with self.connect() as db, db:
            db.execute("BEGIN IMMEDIATE")
            token = db.execute("SELECT * FROM enrollment_tokens WHERE digest=?", (digest,)).fetchone()
            if token["used"] or token["expires_at"] <= now:
                raise HTTPException(401, "Enrollment token expired or consumed")
            agent_uuid, auth_token, signing_key = str(uuid4()), secrets.token_urlsafe(32), secrets.token_hex(32)
            db.execute("INSERT INTO agents(agent_uuid, token_hash, signing_key, hostname, platform, enrolled_at) VALUES (?, ?, ?, ?, ?, ?)",
                       (agent_uuid, hashlib.sha256(auth_token.encode()).hexdigest(), signing_key, body.hostname, body.platform, now))
            db.execute("UPDATE enrollment_tokens SET used=1 WHERE digest=?", (digest,))
        return {"agent_uuid": agent_uuid, "auth_token": auth_token, "signing_key": signing_key, "heartbeat_interval_seconds": 5}

    def authenticate(self, agent_uuid: str, token: str, timestamp: str, signature: str, raw: bytes):
        try:
            agent_uuid = str(UUID(agent_uuid))
            signed_at = int(timestamp)
        except (ValueError, TypeError):
            raise HTTPException(401, "Invalid agent credentials") from None
        if abs(time.time() - signed_at) > 60:
            raise HTTPException(401, "Stale agent signature")
        with self.connect() as db:
            row = db.execute("SELECT token_hash, signing_key FROM agents WHERE agent_uuid=?", (agent_uuid,)).fetchone()
        if row is None or not hmac.compare_digest(row["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
            raise HTTPException(401, "Invalid agent credentials")
        expected = hmac.new(bytes.fromhex(row["signing_key"]), timestamp.encode() + b"\n" + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected.encode(), signature.encode()):
            raise HTTPException(401, "Invalid agent signature")
        return agent_uuid

    def heartbeat(self, body: Heartbeat):
        now = time.time()
        with self.connect() as db, db:
            db.execute("UPDATE agents SET last_seen=?, latency_ms=?, resources=? WHERE agent_uuid=?",
                       (now, body.latency_ms, body.resources.model_dump_json(), str(body.agent_uuid)))
        return {"ok": True, "received_at": now, "heartbeat_interval_seconds": 5}

    def events(self, body: Events):
        payload = json.dumps(body.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        agent_uuid = str(body.agent_uuid)
        with self.connect() as db, db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT digest FROM agent_events WHERE agent_uuid=? AND seq=?", (agent_uuid, body.seq)).fetchone()
            if previous:
                if previous["digest"] != digest:
                    raise HTTPException(409, "Sequence already contains different events")
                return {"ok": True, "seq": body.seq, "duplicate": True, "accepted": 0}
            latest = db.execute("SELECT COALESCE(MAX(seq), 0) FROM agent_events WHERE agent_uuid=?", (agent_uuid,)).fetchone()[0]
            if body.seq != latest + 1:
                raise HTTPException(409, "Events must use the next sequence")
            db.execute("INSERT INTO agent_events VALUES (?, ?, ?, ?, ?)", (agent_uuid, body.seq, digest, payload, time.time()))
        return {"ok": True, "seq": body.seq, "duplicate": False, "accepted": len(body.events)}


    # 조회는 인증 토큰과 서명 키를 돌려주지 않는다.
    _PUBLIC = "agent_uuid, hostname, platform, enrolled_at, last_seen, latency_ms, resources"

    @staticmethod
    def _public(row) -> dict:
        item = dict(row)
        item["resources"] = json.loads(item["resources"]) if item["resources"] else None
        return item

    def agent_count(self) -> int:
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]

    def list_agents(self, limit: int, offset: int) -> dict:
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
            rows = db.execute(f"SELECT {self._PUBLIC} FROM agents ORDER BY hostname, agent_uuid LIMIT ? OFFSET ?",
                              (limit, offset)).fetchall()
        return {"total": total, "now": time.time(), "agents": [self._public(row) for row in rows]}

    def agent(self, agent_uuid: str) -> dict:
        with self.connect() as db:
            row = db.execute(f"SELECT {self._PUBLIC} FROM agents WHERE agent_uuid=?", (agent_uuid,)).fetchone()
        if row is None:
            raise HTTPException(404, "Agent not found")
        return self._public(row)

    def agent_events(self, agent_uuid: str, limit: int, before_seq: int | None) -> dict:
        self.agent(agent_uuid)
        with self.connect() as db:
            rows = db.execute(
                "SELECT seq, received_at, payload FROM agent_events WHERE agent_uuid=? AND seq < ? "
                "ORDER BY seq DESC LIMIT ?",
                (agent_uuid, before_seq if before_seq is not None else 2**63 - 1, limit),
            ).fetchall()
        batches = [{"seq": row["seq"], "received_at": row["received_at"],
                    "events": json.loads(row["payload"])["events"]} for row in rows]
        return {"batches": batches, "next_before_seq": batches[-1]["seq"] if len(batches) == limit else None}


def create_agent_query_router(store: AgentGatewayStore) -> APIRouter:
    """에이전트 조회 API. 콘솔 로그인 사용자(viewer 이상)용이며 에이전트 자격 증명과 무관하다."""
    from fastapi import Depends, Query
    from netwatcher.web.rbac import Role, require_role

    router = APIRouter(prefix="/agents", tags=["agents"], dependencies=[Depends(require_role(Role.VIEWER))])

    def _uuid(value: str) -> str:
        try:
            return str(UUID(value))
        except ValueError:
            raise HTTPException(422, "Invalid agent UUID") from None

    @router.get("")
    async def list_agents(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        return await asyncio.to_thread(store.list_agents, limit, offset)

    @router.get("/{agent_uuid}")
    async def agent(agent_uuid: str):
        return await asyncio.to_thread(store.agent, _uuid(agent_uuid))

    @router.get("/{agent_uuid}/events")
    async def agent_events(agent_uuid: str, limit: int = Query(20, ge=1, le=100),
                           before_seq: int | None = Query(None, ge=1)):
        return await asyncio.to_thread(store.agent_events, _uuid(agent_uuid), limit, before_seq)

    return router


def _ip(address: str) -> str | None:
    host = address.rpartition(":")[0].strip("[]")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def anomaly_alerts(body: Events, hostname: str) -> list[dict]:
    """이상 이벤트만 경보 행으로 만든다. 일반 연결 기록은 경보가 아니다.

    ingest_id는 (agent_uuid, seq, 배치 안 순번)에서 정해지므로 같은 배치를 다시 받아도 경보가 늘지 않는다.
    """
    alerts = []
    for index, event in enumerate(body.events):
        if event.kind != "anomaly":
            continue
        detail = event.detail or f"{event.local_address} -> {event.remote_address} ({event.state})"
        alerts.append({
            "ingest_id": str(uuid5(AGENT_ALERT_NAMESPACE, f"{body.agent_uuid}:{body.seq}:{index}")),
            "engine": "host_agent", "severity": "WARNING",
            "title": f"Host agent anomaly on {hostname}"[:512], "description": detail,
            "source_ip": _ip(event.local_address), "dest_ip": _ip(event.remote_address),
            "timestamp": datetime.fromtimestamp(event.observed_at, timezone.utc).isoformat(),
            "metadata": {"agent_uuid": str(body.agent_uuid), "seq": body.seq, "index": index,
                         "hostname": hostname, "state": event.state,
                         "local_address": event.local_address, "remote_address": event.remote_address},
        })
    return alerts


def create_agent_gateway_router(store: AgentGatewayStore, event_repo=None) -> APIRouter:
    """event_repo가 있으면 이상 이벤트를 경보로 저장한다."""
    router = APIRouter(prefix="/agent", tags=["agent"])

    async def authenticate(request: Request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 256 * 1024:
                raise HTTPException(413, "Agent payload too large")
        # FastAPI caches parsed body before dependency evaluation; signatures cover those exact bytes.
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Missing agent token")
        return await asyncio.to_thread(store.authenticate, request.headers.get("x-agent-uuid", ""),
                                       authorization[7:], request.headers.get("x-agent-timestamp", ""),
                                       request.headers.get("x-agent-signature", ""), bytes(raw))

    @router.post("/enroll", status_code=201)
    def enroll(body: Enrollment):
        return store.enroll(body)

    @router.post("/heartbeat")
    def heartbeat(body: Heartbeat, agent_uuid: str = Depends(authenticate)):
        if str(body.agent_uuid) != agent_uuid:
            raise HTTPException(403, "Agent identity mismatch")
        return store.heartbeat(body)

    @router.post("/events")
    async def events(body: Events, agent_uuid: str = Depends(authenticate)):
        if str(body.agent_uuid) != agent_uuid:
            raise HTTPException(403, "Agent identity mismatch")
        result = await asyncio.to_thread(store.events, body)
        if event_repo is None or not any(event.kind == "anomaly" for event in body.events):
            return result
        # 중복 수신도 다시 저장을 시도한다. 첫 저장이 실패해 에이전트가 재전송한 경우를 살리기 위해서다.
        hostname = (await asyncio.to_thread(store.agent, agent_uuid))["hostname"]
        try:
            await event_repo.insert_batch_mapped(anomaly_alerts(body, hostname))
        except Exception:
            # 연결 기록은 저장됐지만 경보는 아니다. 실패로 알려 에이전트가 같은 배치를 다시 보내게 한다.
            raise HTTPException(503, "Agent events stored but anomaly alerts were not") from None
        return result

    return router
