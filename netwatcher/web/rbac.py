"""역할 기반 접근 제어 (RBAC).

인증 활성화 시 JWT의 role 클레임을 기반으로 최소 역할을 검사한다.
상위 역할은 하위 역할의 접근 권한을 포함한다. 다중 사용자 발급은 별도 계약이다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
import asyncio
from uuid import uuid4
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
    Role.ANALYST: {"read", "acknowledge", "export"},
    Role.VIEWER:  {"read", "export"},
}

ROLE_LEVEL = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}

ADMIN_CHANGE_PREFIXES = (
    "/api/blocks", "/api/blocklist", "/api/whitelist", "/api/rules",
    "/api/devices", "/api/engines", "/api/users",
    "/api/incidents",
    "/api/response-actions", "/api/change-proposals",
)
MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def is_admin_change(path: str, method: str) -> bool:
    if method in MUTATION_METHODS and path.startswith("/api/work-schedules"):
        return True
    if method in MUTATION_METHODS and path.startswith("/api/events/") and path.endswith(("/business-review", "/case", "/work-schedule", "/evidence/pin")):
        return True
    return method in MUTATION_METHODS and any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in ADMIN_CHANGE_PREFIXES
    )


def has_permission(role: Role, action: str) -> bool:
    """주어진 역할이 특정 액션에 대한 권한을 보유하는지 확인한다."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return "*" in perms or action in perms


def require_role(*roles: Role):
    """지정된 최소 역할 중 하나를 충족하는 JWT 검증 의존성을 반환한다.

    사용 예시::

        @router.post("/block", dependencies=[Depends(require_role(Role.ADMIN, Role.ANALYST))])
        async def add_block(...): ...
    """

    async def _dependency(request: Request) -> dict:
        auth_manager: AuthManager | None = request.app.state.auth_manager if hasattr(request.app.state, "auth_manager") else None

        if auth_manager is None or not auth_manager.enabled:
            payload = {"sub": "anonymous", "role": Role.ADMIN.value}
            await _audit_intent(request, payload)
            return payload

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

        from netwatcher.web.auth import AuthStateUnavailable
        try:
            payload = await auth_manager.verify_token_async(auth_header[7:])
        except AuthStateUnavailable:
            raise HTTPException(503,'Account verification unavailable') from None
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        user_role_str = payload.get("role", Role.VIEWER.value)
        try:
            user_role = Role(user_role_str)
        except (ValueError, TypeError):
            raise HTTPException(status_code=403, detail=f"Unknown role: {user_role_str}")

        if not any(ROLE_LEVEL[user_role] >= ROLE_LEVEL[role] for role in roles):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user_role.value}' is not authorized. Required: {[r.value for r in roles]}",
            )
        await _audit_intent(request, payload)
        return payload

    _dependency.required_roles = tuple(roles)
    return _dependency


async def _audit_intent(request: Request, payload: dict) -> None:
    protected = is_admin_change(request.url.path, request.method)
    approval = request.method == "POST" and request.url.path.endswith(("/approve", "/activate"))
    if protected or approval:
        audit = getattr(request.app.state, "audit_logger", None)
        if getattr(request.app.state, "audit_required", False):
            if getattr(request.state, "audit_intent", None) is not None:
                return
            request_id = uuid4().hex
            try:
                async with asyncio.timeout(2):
                    saved = audit is not None and await audit.log(
                        user=str(payload.get("sub", "unknown")),
                        action="authorized_intent", resource=request.url.path,
                        details={"method": request.method, "request_id": request_id},
                        ip=request.client.host if request.client else "",
                    )
            except Exception:
                saved = False
            if not saved:
                raise HTTPException(503, "Required change audit is unavailable")
            request.state.audit_intent = {
                "user": str(payload.get("sub", "unknown")), "request_id": request_id,
            }


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
        except (ValueError, TypeError):
            logger.warning("Unknown role in token: %s", role_str)
            return None
