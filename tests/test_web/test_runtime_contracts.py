"""실제 인증과 앱 상태 연결에 대한 회귀 검사."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

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
