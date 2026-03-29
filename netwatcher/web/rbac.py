"""역할 기반 접근 제어 (RBAC).

multi_user: false일 때는 기존 단일 사용자 인증을 그대로 유지한다.
multi_user: true일 때만 JWT의 role 클레임을 기반으로 접근 제어를 수행한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Request

if TYPE_CHECKING:
    from netwatcher.web.auth import AuthManager

logger = logging.getLogger("netwatcher.web.rbac")


class Role(str, Enum):
    ADMIN   = "admin"
    ANALYST = "analyst"
    VIEWER  = "viewer"


ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN:   {"*"},
    Role.ANALYST: {"read", "acknowledge", "block", "unblock", "export"},
    Role.VIEWER:  {"read", "export"},
}


def has_permission(role: Role, action: str) -> bool:
    """주어진 역할이 특정 액션에 대한 권한을 보유하는지 확인한다."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return "*" in perms or action in perms


def require_role(*roles: Role):
    """JWT role 클레임 검증 FastAPI 의존성을 반환한다.

    사용 예시::

        @router.post("/block", dependencies=[Depends(require_role(Role.ADMIN, Role.ANALYST))])
        async def add_block(...): ...
    """

    async def _dependency(request: Request) -> dict:
        auth_manager: AuthManager | None = request.app.state.auth_manager if hasattr(request.app.state, "auth_manager") else None

        if auth_manager is None or not auth_manager.enabled:
            return {"sub": "anonymous", "role": Role.ADMIN.value}

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        payload = auth_manager.verify_token(auth_header[7:])
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        user_role_str = payload.get("role", Role.VIEWER.value)
        try:
            user_role = Role(user_role_str)
        except ValueError:
            raise HTTPException(status_code=403, detail=f"Unknown role: {user_role_str}")

        if user_role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user_role.value}' is not authorized. Required: {[r.value for r in roles]}",
            )
        return payload

    return _dependency


class RBACManager:
    """RBAC 관리 유틸리티.

    AuthManager를 래핑하여 토큰에서 역할을 추출하고 권한을 검증한다.
    """

    def __init__(self, auth_manager: AuthManager) -> None:
        self._auth = auth_manager

    def check_permission(self, token: str, action: str) -> bool:
        """토큰의 role 클레임이 주어진 액션을 허용하는지 검증한다."""
        role = self.get_user_role(token)
        if role is None:
            return False
        return has_permission(role, action)

    def get_user_role(self, token: str) -> Role | None:
        """토큰에서 사용자 역할을 추출한다. 유효하지 않으면 None."""
        payload = self._auth.verify_token(token)
        if payload is None:
            return None
        role_str = payload.get("role", Role.VIEWER.value)
        try:
            return Role(role_str)
        except ValueError:
            logger.warning("Unknown role in token: %s", role_str)
            return None
