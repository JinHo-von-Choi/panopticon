"""Tests for JWT authentication system."""

from __future__ import annotations

import hmac
from unittest.mock import patch

import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager
from netwatcher.web.server import create_app


def _make_auth_config(tmp_path, monkeypatch, enabled=True, password="testpassword123"):
    """Create a Config with explicit auth settings, overriding env vars."""
    # Override env vars to prevent .env / autouse fixture interference
    if enabled:
        monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "true")
    else:
        monkeypatch.setenv("NETWATCHER_LOGIN_ENABLED", "false")
    if password:
        monkeypatch.setenv("NETWATCHER_LOGIN_PASSWORD", password)
    else:
        monkeypatch.setenv("NETWATCHER_LOGIN_PASSWORD", "")

    yaml_content = f"""
netwatcher:
  interface: null
  postgresql:
    enabled: true
    host: "localhost"
    port: 5432
    database: "netwatcher"
    username: "home"
    password: ""
    pool_size: 5
    ssl_mode: "disable"
  auth:
    enabled: {str(enabled).lower()}
    username: "admin"
    password: "{password}"
    token_expire_hours: 24
  logging:
    level: DEBUG
    directory: "{tmp_path / 'logs'}"
  alerts:
    rate_limit:
      window_seconds: 300
      max_per_key: 5
    channels: {{}}
  whitelist:
    ips: []
    ip_ranges: []
    macs: []
    domains: []
    domain_suffixes: []
  web:
    enable_docs: false
"""
    config_file = tmp_path / "auth_config.yaml"
    config_file.write_text(yaml_content)
    return Config.load(config_file)


def _make_stub_dispatcher(config):
    """Create a minimal dispatcher stub for testing."""
    import asyncio
    d = AlertDispatcher.__new__(AlertDispatcher)
    d._config         = config
    d._event_repo     = None
    d._queue          = asyncio.Queue(maxsize=10000)
    d._task           = None
    d._rate_limiter   = None
    d._channels       = []
    d._ws_subscribers = set()
    return d


class TestAuthManager:
    def test_jwt_secret_independent_of_password(self, tmp_path, monkeypatch):
        """JWT secret should NOT be derived from the password."""
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        import hashlib
        pw_hash = hashlib.sha256("testpassword123".encode()).hexdigest()
        assert mgr._secret != pw_hash

    def test_jwt_secret_auto_generated(self, tmp_path, monkeypatch):
        """Without NETWATCHER_JWT_SECRET env, secret should be auto-generated."""
        monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        assert len(mgr._secret) > 32

    def test_jwt_secret_from_env(self, tmp_path, monkeypatch):
        """NETWATCHER_JWT_SECRET env should be used if set."""
        monkeypatch.setenv("NETWATCHER_JWT_SECRET", "my-env-secret")
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        assert mgr._secret == "my-env-secret"

    def test_authenticate_success(self, tmp_path, monkeypatch):
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        token = mgr.authenticate("admin", "testpassword123")
        assert token is not None
        payload = mgr.verify_token(token)
        assert payload is not None
        assert payload["sub"] == "admin"

    def test_authenticate_wrong_password(self, tmp_path, monkeypatch):
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        token = mgr.authenticate("admin", "wrongpassword")
        assert token is None

    def test_authenticate_wrong_username(self, tmp_path, monkeypatch):
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        token = mgr.authenticate("wronguser", "testpassword123")
        assert token is None

    def test_timing_safe_comparison(self, tmp_path, monkeypatch):
        """authenticate() should use hmac.compare_digest for username, bcrypt for password."""
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        with patch("netwatcher.web.auth.hmac.compare_digest", wraps=hmac.compare_digest) as mock_cmp:
            mgr.authenticate("admin", "testpassword123")
            # username: hmac.compare_digest, password: bcrypt.checkpw
            assert mock_cmp.call_count == 1

    def test_expired_token(self, tmp_path, monkeypatch):
        cfg = _make_auth_config(tmp_path, monkeypatch)
        mgr = AuthManager(cfg)
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "admin",
            "iat": now - timedelta(hours=48),
            "exp": now - timedelta(hours=24),
        }
        expired_token = jwt.encode(payload, mgr._secret, algorithm="HS256")
        assert mgr.verify_token(expired_token) is None

    def test_disabled_when_no_password(self, tmp_path, monkeypatch):
        """Auth should auto-disable when enabled=true but password is empty."""
        cfg = _make_auth_config(tmp_path, monkeypatch, enabled=True, password="")
        mgr = AuthManager(cfg)
        assert mgr.enabled is False


class TestAuthEndpoints:
    @pytest.fixture
    def auth_app(self, tmp_path, monkeypatch, event_repo, device_repo, stats_repo):
        cfg = _make_auth_config(tmp_path, monkeypatch, enabled=True, password="testpassword123")
        dispatcher = _make_stub_dispatcher(cfg)
        return create_app(
            config=cfg,
            event_repo=event_repo,
            device_repo=device_repo,
            stats_repo=stats_repo,
            dispatcher=dispatcher,
        )

    @pytest.fixture
    def no_auth_app(self, tmp_path, monkeypatch, event_repo, device_repo, stats_repo):
        cfg = _make_auth_config(tmp_path, monkeypatch, enabled=False, password="")
        dispatcher = _make_stub_dispatcher(cfg)
        return create_app(
            config=cfg,
            event_repo=event_repo,
            device_repo=device_repo,
            stats_repo=stats_repo,
            dispatcher=dispatcher,
        )

    @pytest.mark.asyncio
    async def test_login_success(self, auth_app):
        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "testpassword123"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "token" in data

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, auth_app):
        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_endpoint_no_token(self, auth_app):
        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/events")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_protected_endpoint_valid_token(self, auth_app):
        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            login_resp = await client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "testpassword123"},
            )
            assert login_resp.status_code == 200
            token = login_resp.json()["token"]
            resp = await client.get(
                "/api/events",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_protected_endpoint_expired_token(self, auth_app, tmp_path, monkeypatch):
        cfg = _make_auth_config(tmp_path, monkeypatch, enabled=True, password="testpassword123")
        mgr = AuthManager(cfg)
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "admin",
            "iat": now - timedelta(hours=48),
            "exp": now - timedelta(hours=24),
        }
        expired_token = jwt.encode(payload, mgr._secret, algorithm="HS256")

        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/events",
                headers={"Authorization": f"Bearer {expired_token}"},
            )
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_status_when_disabled(self, no_auth_app):
        transport = ASGITransport(app=no_auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/auth/status")
            assert resp.status_code == 200
            assert resp.json() == {"enabled": False}

    @pytest.mark.asyncio
    async def test_auth_status_when_enabled(self, auth_app):
        transport = ASGITransport(app=auth_app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/auth/status")
            assert resp.status_code == 200
            assert resp.json() == {"enabled": True}
