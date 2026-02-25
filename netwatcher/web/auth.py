"""NetWatcher 대시보드용 JWT 인증.

작성자: 최진호
수정일: 2026-02-20
"""

from __future__ import annotations

import hmac
import logging
import os
import secrets

import bcrypt
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from netwatcher.utils.config import Config

logger = logging.getLogger(__name__)

# AuthMiddleware에서 인증을 면제할 경로 접두사
_PUBLIC_PREFIXES = (
    "/api/auth/login",
    "/api/auth/status",
    "/docs",
    "/openapi.json",
    "/health",
    "/metrics",
)

# 정적 리소스 경로 (인증 면제)
_STATIC_PREFIXES = (
    "/",
    "/css/",
    "/js/",
    "/img/",
)


class AuthManager:
    """JWT 기반 단일 사용자 인증 관리자."""

    def __init__(self, config: Config) -> None:
        """설정에서 인증 파라미터를 로드하고 JWT 시크릿을 초기화한다."""
        auth_cfg          = config.section("auth")
        enabled_raw       = auth_cfg.get("enabled", False)
        self._enabled     = str(enabled_raw).lower() == "true" if isinstance(enabled_raw, str) else bool(enabled_raw)
        self._username      = auth_cfg.get("username", "admin")
        self._expire_hours  = int(auth_cfg.get("token_expire_hours", 24))

        # 비밀번호: bcrypt 해시 또는 평문 → 해시 변환
        raw_password = auth_cfg.get("password", "")
        self._password_hash: bytes | None = None
        if raw_password:
            if raw_password.startswith(("$2b$", "$2a$")):
                self._password_hash = raw_password.encode("utf-8")
            else:
                self._password_hash = bcrypt.hashpw(
                    raw_password.encode("utf-8"), bcrypt.gensalt()
                )
                logger.warning(
                    "auth.password is plaintext. "
                    "Generate a hash with: python -c \"import bcrypt; "
                    "print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt()).decode())\"",
                )

        # JWT 시크릿: 환경변수 > config > 자동 생성
        jwt_secret = os.environ.get("NETWATCHER_JWT_SECRET", "")
        if not jwt_secret:
            jwt_secret = auth_cfg.get("jwt_secret", "")
        if not jwt_secret:
            jwt_secret = secrets.token_urlsafe(64)
            logger.warning(
                "JWT secret auto-generated. Set NETWATCHER_JWT_SECRET for persistent tokens."
            )
        self._secret = jwt_secret

        if self._enabled and not self._password_hash:
            logger.warning("auth.enabled=true but auth.password is empty — disabling authentication")
            self._enabled = False

        if self._enabled:
            logger.info("Dashboard authentication enabled (user=%s, expire=%dh)", self._username, self._expire_hours)

    @property
    def enabled(self) -> bool:
        """인증 기능 활성화 여부를 반환한다."""
        return self._enabled

    def authenticate(self, username: str, password: str) -> str | None:
        """자격증명 검증 후 JWT 토큰을 반환한다. 실패 시 None."""
        if not hmac.compare_digest(username, self._username):
            return None
        if self._password_hash is None:
            return None
        if not bcrypt.checkpw(password.encode("utf-8"), self._password_hash):
            return None
        now = datetime.now(timezone.utc)
        payload = {
            "sub": username,
            "iat": now,
            "exp": now + timedelta(hours=self._expire_hours),
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")

    def verify_token(self, token: str) -> dict | None:
        """JWT 토큰을 디코딩하고 유효성을 검증한다. 유효하면 payload dict 반환, 실패 시 None."""
        try:
            return jwt.decode(token, self._secret, algorithms=["HS256"])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None


class AuthMiddleware(BaseHTTPMiddleware):
    """HTTP API 요청에 JWT Bearer 토큰 인증을 적용하는 미들웨어."""

    def __init__(self, app, auth_manager: AuthManager) -> None:
        """AuthManager를 주입받아 미들웨어를 초기화한다."""
        super().__init__(app)
        self._auth = auth_manager

    async def dispatch(self, request: Request, call_next):
        """요청 경로에 따라 JWT 인증을 수행하거나 면제한다."""
        if not self._auth.enabled:
            return await call_next(request)

        path = request.url.path

        # 공개 엔드포인트 면제
        for prefix in _PUBLIC_PREFIXES:
            if path == prefix or path.startswith(prefix + "/"):
                return await call_next(request)

        # 정적 리소스 면제 (루트 index.html 포함)
        if path == "/":
            return await call_next(request)
        for prefix in _STATIC_PREFIXES:
            if prefix != "/" and path.startswith(prefix):
                return await call_next(request)

        # WebSocket 경로 면제 (토큰은 쿼리 파라미터로 전달)
        if path.startswith("/ws/"):
            return await call_next(request)

        # /api/* 경로만 인증 필요
        if path.startswith("/api/"):
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return JSONResponse({"error": "Missing or invalid Authorization header"}, status_code=401)
            token = auth_header[7:]
            if not self._auth.verify_token(token):
                return JSONResponse({"error": "Invalid or expired token"}, status_code=401)

        return await call_next(request)
