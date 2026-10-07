"""실제 인증과 앱 상태 연결에 대한 회귀 검사."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import bcrypt
import jwt
import pytest
from fastapi import Depends
from httpx import ASGITransport, AsyncClient

from netwatcher.observability.observation import ObservationService
from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager
from netwatcher.web.rbac import Role, require_role
from netwatcher.web.server import create_app
from netwatcher.web.api_rate_limiter import APIRateLimiter
from netwatcher.observability.health import HealthChecker


@pytest.fixture
def runtime_app(tmp_path, monkeypatch):
    monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
    feed_config = Path(__file__).resolve().parents[2] / "config/threatfeeds.yaml"
    monkeypatch.chdir(tmp_path)
    config = Config({
        "auth": {
            "enabled": True,
            "username": "admin",
            "password": bcrypt.hashpw(b"test-password", bcrypt.gensalt(rounds=4)).decode(),
            "jwt_secret": "runtime-contract-test-secret-at-least-32-bytes",
        },
        "threatfeeds": {"config_path": str(feed_config)},
    })
    auth = AuthManager(config)
    observation = ObservationService(sensor_id="test-sensor")
    feeds = FeedManager(config)
    app = create_app(config, None, None, None, None, auth_manager=auth,
                     observation_service=observation, feed_manager=feeds)
    for role in Role:
        def endpoint(payload=Depends(require_role(role))):
            return {"role": payload["role"]}
        app.add_api_route(f"/api/minimum/{role.value}", endpoint)
    return app, config, observation, feeds


@pytest.mark.asyncio
async def test_login_admin_can_read_observation(runtime_app):
    app, _, observation, _ = runtime_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        login = await client.post("/api/auth/login", json={"username": "admin", "password": "test-password"})
        assert login.status_code == 200
        response = await client.get("/api/observation", headers={"Authorization": f"Bearer {login.json()['token']}"})
    assert response.status_code == 200
    assert response.json()["state"] == observation.snapshot()["state"]


@pytest.mark.asyncio
@pytest.mark.parametrize("role,expected", [
    ("admin", [200, 200, 200]),
    ("analyst", [403, 200, 200]),
    ("viewer", [403, 403, 200]),
    ("unknown", [403, 403, 403]),
    (None, [403, 403, 403]),
    (["admin"], [403, 403, 403]),
])
async def test_minimum_role_matrix(runtime_app, role, expected):
    app, config, _, _ = runtime_app
    token = jwt.encode({"sub": "test-user", "role": role,
                        "exp": datetime.now(timezone.utc) + timedelta(minutes=1)},
                       config.section("auth")["jwt_secret"], algorithm="HS256")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        statuses = [(await client.get(f"/api/minimum/{minimum.value}",
                                     headers={"Authorization": f"Bearer {token}"})).status_code
                    for minimum in Role]
    assert statuses == expected


@pytest.mark.asyncio
async def test_support_profile_includes_runtime_state(runtime_app):
    app, _, observation, feeds = runtime_app
    token = app.state.auth_manager.authenticate("admin", "test-password")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/support-profile", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["observation"]["state"] == observation.snapshot()["state"]
    assert data["feeds"] == feeds.feed_health()
    for violation in feeds.health_as_violations():
        assert violation.as_dict() in data["violations"]


@pytest.mark.asyncio
async def test_renewed_token_shares_user_budget(runtime_app):
    app, config, _, _ = runtime_app
    limiter = APIRateLimiter(requests_per_minute=1, burst=0)
    app.add_api_route("/api/budget", lambda: {"ok": True},
                      dependencies=[Depends(limiter.as_dependency())])
    def token(user, nonce):
        return jwt.encode({"sub": user, "role": "admin", "nonce": nonce,
                           "exp": datetime.now(timezone.utc) + timedelta(minutes=1)},
                          config.section("auth")["jwt_secret"], algorithm="HS256")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        async def get(user, nonce):
            return await client.get("/api/budget", headers={"Authorization": "Bearer " + token(user, nonce)})
        assert (await get("alice", 1)).status_code == 200
        renewed = await get("alice", 2)
        assert renewed.status_code == 429
        assert renewed.headers["Retry-After"] == "60"
        assert (await get("bob", 1)).status_code == 200
        assert (await client.get("/api/budget", headers={"Authorization": "Bearer forged"})).status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("role,expected", [("viewer", 403), ("analyst", 200), ("admin", 200)])
async def test_write_routes_without_local_role_dependency_are_protected(runtime_app, role, expected):
    app, config, _, _ = runtime_app
    app.add_api_route("/api/test-write", lambda: {"changed": True}, methods=["POST"])
    token = jwt.encode({"sub": "test-writer", "role": role,
                        "exp": datetime.now(timezone.utc) + timedelta(minutes=1)},
                       config.section("auth")["jwt_secret"], algorithm="HS256")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/api/test-write", headers={"Authorization": "Bearer " + token})).status_code == expected


@pytest.mark.asyncio
async def test_login_limit_cannot_be_reset_by_username_or_forwarded_ip(runtime_app):
    app, _, _, _ = runtime_app
    app.state.login_limiter = APIRateLimiter(requests_per_minute=2, burst=0)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for username in ("admin", "different"):
            assert (await client.post("/api/auth/login", json={"username": username, "password": "wrong"})).status_code == 401
        response = await client.post("/api/auth/login", json={"username": "admin", "password": "test-password"},
                                     headers={"X-Forwarded-For": "192.0.2.1"})
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "60"


@pytest.mark.asyncio
async def test_bounded_fallback_when_redis_fails():
    redis = SimpleNamespace(pipeline=lambda: (_ for _ in ()).throw(ConnectionError()))
    limiter = APIRateLimiter(redis_client=redis, requests_per_minute=2, burst=0, max_keys=2)
    assert await limiter.check("a")
    assert await limiter.check("a")
    assert not await limiter.check("a")
    assert await limiter.check("b")
    for i in range(100):
        assert not await limiter.check(f"extra-{i}")
    assert len(limiter._buckets) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("authenticated", [True, False])
async def test_approval_fails_closed_without_durable_audit(runtime_app, authenticated):
    app, _, _, _ = runtime_app
    app.state.audit_required = True
    app.state.audit_logger = SimpleNamespace(log=AsyncMock(return_value=False))
    calls = []
    @app.post("/api/test/approve", dependencies=[Depends(require_role(Role.ADMIN))])
    def approve():
        calls.append("apply")
        return {"applied": True}
    token = app.state.auth_manager.authenticate("admin", "test-password")
    if not authenticated:
        app.state.auth_manager._enabled = False
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {token}"} if authenticated else {}
        assert (await client.post("/api/test/approve", headers=headers)).status_code == 503
        assert calls == []
        app.state.audit_logger.log.return_value = True
        assert (await client.post("/api/test/approve", headers=headers)).status_code == 200
        assert calls == ["apply"]


@pytest.mark.asyncio
async def test_liveness_is_separate_from_readiness(runtime_app):
    app, _, _, _ = runtime_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/health")).status_code == 200
        response = await client.get("/ready")
        assert response.status_code == 503
        assert response.json() == {"status": "not_ready"}
        assert (await client.get("/api/health")).status_code == 401


@pytest.mark.asyncio
async def test_real_component_interfaces_and_timeout():
    sniffer = SimpleNamespace(is_running=True)
    registry = SimpleNamespace(_engines=[SimpleNamespace(enabled=True)])
    dispatcher = SimpleNamespace(_queue=asyncio.Queue(maxsize=10))
    checker = HealthChecker(sniffer=sniffer, registry=registry, dispatcher=dispatcher)
    result = await checker.readiness()
    assert result["components"]["sniffer"]["status"] == "healthy"
    assert result["components"]["engines"]["enabled"] == 1
    assert not result["ready"]
    async def never_acquire():
        await asyncio.Event().wait()
    class Acquisition:
        async def __aenter__(self):
            return await never_acquire()
        async def __aexit__(self, *args):
            pass
    checker._database = SimpleNamespace(pool=SimpleNamespace(acquire=Acquisition))
    checker._timeout_seconds = 0.01
    assert (await checker.readiness())["components"]["database"]["reason"] == "TimeoutError"


@pytest.mark.asyncio
async def test_failed_state_queries_report_unknown_without_exception_details(runtime_app):
    app, _, _, _ = runtime_app
    def fail():
        raise RuntimeError("credential=do-not-expose")
    app.state.observation_service = SimpleNamespace(snapshot=fail)
    app.state.feed_manager = SimpleNamespace(feed_health=fail)
    token = app.state.auth_manager.authenticate("admin", "test-password")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/support-profile", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["observation"]["state"] == "unknown"
    assert response.json()["feeds"]["status"] == "unknown"
    assert "do-not-expose" not in response.text
