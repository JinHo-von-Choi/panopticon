"""Persistent single-console enrollment and signed host telemetry gateway."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field


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


def create_agent_gateway_router(store: AgentGatewayStore) -> APIRouter:
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
    def events(body: Events, agent_uuid: str = Depends(authenticate)):
        if str(body.agent_uuid) != agent_uuid:
            raise HTTPException(403, "Agent identity mismatch")
        return store.events(body)

    return router
