"""RBAC 역할 검증 및 권한 매트릭스 테스트."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from netwatcher.web.rbac import (
    ROLE_PERMISSIONS,
    Role,
    RBACManager,
    has_permission,
    require_role,
)


class TestRolePermissions:
    """역할별 권한 매트릭스 검증."""

    def test_admin_has_wildcard(self):
        assert "*" in ROLE_PERMISSIONS[Role.ADMIN]

    def test_admin_has_all_permissions(self):
        assert has_permission(Role.ADMIN, "read")
        assert has_permission(Role.ADMIN, "acknowledge")
        assert has_permission(Role.ADMIN, "block")
        assert has_permission(Role.ADMIN, "unblock")
        assert has_permission(Role.ADMIN, "export")
        assert has_permission(Role.ADMIN, "any_arbitrary_action")

    def test_analyst_permissions(self):
        assert has_permission(Role.ANALYST, "read")
        assert has_permission(Role.ANALYST, "acknowledge")
        assert has_permission(Role.ANALYST, "block")
        assert has_permission(Role.ANALYST, "unblock")
        assert has_permission(Role.ANALYST, "export")
        assert not has_permission(Role.ANALYST, "admin_only_action")

    def test_viewer_permissions(self):
        assert has_permission(Role.VIEWER, "read")
        assert has_permission(Role.VIEWER, "export")
        assert not has_permission(Role.VIEWER, "acknowledge")
        assert not has_permission(Role.VIEWER, "block")
        assert not has_permission(Role.VIEWER, "unblock")

    def test_role_enum_values(self):
        assert Role.ADMIN.value == "admin"
        assert Role.ANALYST.value == "analyst"
        assert Role.VIEWER.value == "viewer"


class TestRBACManager:
    """RBACManager 유닛 테스트."""

    def _make_auth_manager(self, role: str = "admin"):
        mgr = MagicMock()
        mgr.verify_token.return_value = {"sub": "testuser", "role": role}
        return mgr

    def test_check_permission_admin(self):
        auth = self._make_auth_manager("admin")
        rbac = RBACManager(auth)
        assert rbac.check_permission("fake_token", "read") is True
        assert rbac.check_permission("fake_token", "block") is True
        assert rbac.check_permission("fake_token", "any_action") is True

    def test_check_permission_viewer(self):
        auth = self._make_auth_manager("viewer")
        rbac = RBACManager(auth)
        assert rbac.check_permission("fake_token", "read") is True
        assert rbac.check_permission("fake_token", "block") is False
        assert rbac.check_permission("fake_token", "acknowledge") is False

    def test_check_permission_invalid_token(self):
        auth = MagicMock()
        auth.verify_token.return_value = None
        rbac = RBACManager(auth)
        assert rbac.check_permission("bad_token", "read") is False

    def test_get_user_role(self):
        auth = self._make_auth_manager("analyst")
        rbac = RBACManager(auth)
        assert rbac.get_user_role("fake_token") == Role.ANALYST

    def test_get_user_role_unknown(self):
        auth = self._make_auth_manager("superadmin")
        rbac = RBACManager(auth)
        assert rbac.get_user_role("fake_token") is None

    def test_get_user_role_invalid_token(self):
        auth = MagicMock()
        auth.verify_token.return_value = None
        rbac = RBACManager(auth)
        assert rbac.get_user_role("bad_token") is None


class TestRequireRoleDependency:
    """require_role FastAPI 의존성 통합 테스트."""

    def _build_app(self, auth_manager, roles):
        app = FastAPI()
        app.state.auth_manager = auth_manager
        dep = require_role(*roles)

        @app.get("/test", dependencies=[])
        async def test_endpoint(payload: dict = pytest.importorskip("fastapi").Depends(dep)):
            return {"user": payload.get("sub"), "role": payload.get("role")}

        return app

    def _make_token(self, secret: str, role: str, sub: str = "admin") -> str:
        now = datetime.now(timezone.utc)
        return jwt.encode(
            {"sub": sub, "role": role, "iat": now, "exp": now + timedelta(hours=1)},
            secret,
            algorithm="HS256",
        )

    @pytest.mark.asyncio
    async def test_no_auth_manager_allows_access(self):
        """auth_manager 없으면 anonymous admin으로 통과."""
        app = FastAPI()

        dep = require_role(Role.ADMIN)

        @app.get("/test")
        async def test_endpoint(payload: dict = pytest.importorskip("fastapi").Depends(dep)):
            return {"role": payload.get("role")}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test")
            assert resp.status_code == 200
            assert resp.json()["role"] == "admin"

    @pytest.mark.asyncio
    async def test_disabled_auth_allows_access(self):
        """인증 비활성화 시 anonymous admin으로 통과."""
        auth = MagicMock()
        auth.enabled = False
        app = self._build_app(auth, [Role.ADMIN])

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test")
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self):
        auth = MagicMock()
        auth.enabled = True
        app = self._build_app(auth, [Role.ADMIN])

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test")
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self):
        auth = MagicMock()
        auth.enabled = True
        auth.verify_token.return_value = None
        app = self._build_app(auth, [Role.ADMIN])

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test", headers={"Authorization": "Bearer bad"})
            assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_role_returns_403(self):
        auth = MagicMock()
        auth.enabled = True
        auth.verify_token.return_value = {"sub": "user1", "role": "viewer"}
        app = self._build_app(auth, [Role.ADMIN])

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test", headers={"Authorization": "Bearer tok"})
            assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_correct_role_passes(self):
        auth = MagicMock()
        auth.enabled = True
        auth.verify_token.return_value = {"sub": "admin1", "role": "admin"}
        app = self._build_app(auth, [Role.ADMIN])

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test", headers={"Authorization": "Bearer tok"})
            assert resp.status_code == 200
            assert resp.json()["user"] == "admin1"

    @pytest.mark.asyncio
    async def test_multiple_allowed_roles(self):
        auth = MagicMock()
        auth.enabled = True
        auth.verify_token.return_value = {"sub": "analyst1", "role": "analyst"}
        app = self._build_app(auth, [Role.ADMIN, Role.ANALYST])

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/test", headers={"Authorization": "Bearer tok"})
            assert resp.status_code == 200
