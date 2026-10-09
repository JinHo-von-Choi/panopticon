"""실제 PostgreSQL 감사 저장과 승인 전 차단을 검증한다."""

import bcrypt
import asyncio
from types import SimpleNamespace
import pytest
from fastapi import Depends
from httpx import AsyncClient, ASGITransport

from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.server import create_app
from netwatcher.observability.health import HealthChecker
from netwatcher.observability.observation import ObservationService
from netwatcher.response.blocker import BlockManager


@pytest.mark.asyncio
async def test_runtime_audit_is_durable_and_omits_request_secrets(db, monkeypatch):
    monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
    config = Config({"auth": {"enabled": True, "username": "admin",
        "password": bcrypt.hashpw(b"test-password", bcrypt.gensalt(rounds=4)).decode(),
        "jwt_secret": "test-audit-secret-at-least-thirty-two-bytes"}})
    auth = AuthManager(config)
    audit = AuditLogger(db.pool)
    observation = ObservationService(sensor_id="audit-test")
    observation.mark_heartbeat()
    health = HealthChecker(database=db, sniffer=SimpleNamespace(is_running=True),
                           registry=SimpleNamespace(_engines=[SimpleNamespace(enabled=True)]),
                           dispatcher=SimpleNamespace(_queue=asyncio.Queue(maxsize=10)),
                           observation=observation)
    app = create_app(config, None, None, None, None, auth_manager=auth,
                     audit_logger=audit, audit_required=True, health_checker=health)
    applications = []
    @app.post("/api/test/approve", dependencies=[Depends(require_role(Role.ADMIN))])
    async def approve():
        applications.append("applied")
        return {"ok": True}
    token = auth.authenticate("admin", "test-password")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/ready")).status_code == 200
        health.set_sniffer(SimpleNamespace(is_running=False))
        assert (await client.get("/ready")).status_code == 503
        response = await client.post("/api/test/approve", headers={"Authorization": "Bearer " + token},
                                     json={"password": "never-record-this", "payload": "never-record-payload"})
        assert response.status_code == 200
        entries = await audit.query()
        async with db.pool.acquire() as conn:
            assert await conn.fetchval("SELECT bool_and(jsonb_typeof(details)='object') FROM audit_log")
        assert {row["action"] for row in entries} == {"authorized_intent", "api_mutation"}
        assert all(row["user"] == "admin" for row in entries)
        assert "never-record" not in str(entries)
        assert token not in str(entries)
        async with db.pool.acquire() as conn:
            await conn.execute("DROP TABLE audit_log")
        rejected = await client.post("/api/test/approve", headers={"Authorization": "Bearer " + token})
        assert rejected.status_code == 503
        assert applications == ["applied"]


@pytest.mark.asyncio
async def test_block_change_requires_real_durable_audit(db, config):
    audit = AuditLogger(db.pool)
    manager = BlockManager(enabled=True, backend="mock", whitelist=[])
    app = create_app(config, None, None, None, None, block_manager=manager,
                     audit_logger=audit, audit_required=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/blocks", json={"ip": "192.0.2.10"})
        assert response.status_code == 200
        entries = await audit.query()
        assert {entry["action"] for entry in entries} == {"authorized_intent", "change_prepared", "api_mutation"}
        assert {entry["details"]["request_id"] for entry in entries} == {response.headers["X-Request-ID"]}
        assert len(manager.get_active_blocks()) == 1

        history = await client.get("/api/audit/changes/" + response.headers["X-Request-ID"])
        assert history.status_code == 200, history.text
        assert history.json()["outcome"] == "completed"
        assert history.json()["requires_reconciliation"] is False
        result = history.json()["entries"][-1]["details"]
        assert result["before"]["active"] is False
        assert result["after"]["active"] is True
        async with db.pool.acquire() as conn:
            await conn.execute("DROP TABLE audit_log")
        history = await client.get("/api/audit/changes/" + response.headers["X-Request-ID"])
        assert history.status_code == 503
        response = await client.delete("/api/blocks/192.0.2.10")
        assert response.status_code == 503
        assert len(manager.get_active_blocks()) == 1

@pytest.mark.asyncio
async def test_legacy_audit_conversion_preserves_records(db, monkeypatch):
    import importlib.util
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "alembic/versions/019_audit_request_index.py"
    spec = importlib.util.spec_from_file_location("audit_conversion", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    statements = []
    monkeypatch.setattr(migration.op, "execute", statements.append)
    migration.upgrade()
    request_id = "a" * 32
    async with db.pool.acquire() as conn:
        for details in ({"request_id": request_id}, json.dumps({"request_id": request_id}), "not-json"):
            await conn.execute("INSERT INTO audit_log(action, details) VALUES ('authorized_intent',$1::jsonb)", details)
        for statement in statements:
            await conn.execute(statement)
        assert await conn.fetchval("SELECT count(*) FROM audit_log") == 3
        assert await conn.fetchval("SELECT count(*) FROM audit_log WHERE details->>'request_id'=$1", request_id) == 2
        assert await conn.fetchval("SELECT count(*) FROM audit_log WHERE jsonb_typeof(details)='string'") == 1
