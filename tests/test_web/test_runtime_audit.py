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
        assert {row["action"] for row in entries} == {"authorized_intent", "api_mutation"}
        assert all(row["user"] == "admin" for row in entries)
        assert "never-record" not in str(entries)
        assert token not in str(entries)
        async with db.pool.acquire() as conn:
            await conn.execute("DROP TABLE audit_log")
        rejected = await client.post("/api/test/approve", headers={"Authorization": "Bearer " + token})
        assert rejected.status_code == 503
        assert applications == ["applied"]
