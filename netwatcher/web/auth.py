"""NetWatcher 대시보드용 JWT 인증.

작성자: 최진호
수정일: 2026-02-20
"""

from __future__ import annotations

import asyncio
import asyncpg
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
    "/api/auth/oidc",
    "/health",
    "/ready",
    "/metrics",
)

# 정적 리소스 경로 (인증 면제)
_STATIC_PREFIXES = (
    "/",
    "/css/",
    "/js/",
    "/img/",
    "/fonts/",
    "/locales/",
)


class AuthStateUnavailable(RuntimeError):
    pass


class AuthManager:
    """설정 계정 또는 DB 관리 계정의 로그인과 JWT 검증을 담당한다."""

    def __init__(self, config: Config, *, users=None) -> None:
        """설정에서 인증 파라미터를 로드하고 JWT 시크릿을 초기화한다."""
        auth_cfg          = config.section("auth")
        enabled_raw       = auth_cfg.get("enabled", False)
        self._enabled     = str(enabled_raw).lower() == "true" if isinstance(enabled_raw, str) else bool(enabled_raw)
        multi_raw = auth_cfg.get('multi_user', False)
        self.multi_user = str(multi_raw).lower() == 'true' if isinstance(multi_raw, str) else bool(multi_raw)
        self.users = users if self.multi_user else None
        if self.multi_user and (not self._enabled or self.users is None):
            raise ValueError('Managed accounts require authentication and account storage')
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
        if not jwt_secret and self.multi_user:
            raise ValueError('Managed accounts require a persistent JWT secret')
        if not jwt_secret:
            jwt_secret = secrets.token_urlsafe(64)
            logger.warning(
                "JWT secret auto-generated. Set NETWATCHER_JWT_SECRET for persistent tokens."
            )
        self._secret = jwt_secret

        if self._enabled and not self._password_hash and not self.multi_user:
            raise ValueError(
                "auth.enabled=true but auth.password is empty. "
                "Set a password via NETWATCHER_LOGIN_PASSWORD env var or auth.password in config, "
                "or explicitly set auth.enabled=false."
            )

        if self._enabled:
            logger.info("Dashboard authentication enabled (user=%s, expire=%dh)", self._username, self._expire_hours)

    @property
    def enabled(self) -> bool:
        """인증 기능 활성화 여부를 반환한다."""
        return self._enabled

    def authenticate(self, username: str, password: str) -> str | None:
        """자격증명 검증 후 JWT 토큰을 반환한다. 실패 시 None.

        단일 사용자 설정의 역할은 admin이다. 관리 계정은 authenticate_async를 쓴다.
        """
        if self.multi_user:
            return None
        if not isinstance(password,str) or len(password.encode())>72:
            return None
        if not isinstance(username,str) or not username.isascii():return None
        if not hmac.compare_digest(username, self._username):
            return None
        if self._password_hash is None:
            return None
        if not bcrypt.checkpw(password.encode("utf-8"), self._password_hash):
            return None
        now = datetime.now(timezone.utc)
        payload = {
            "sub": username,
            "role": "admin",
            "iat": now,
            "exp": now + timedelta(hours=self._expire_hours),
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")

    async def initialize(self):
        if self.multi_user:
            async with asyncio.timeout(5):
                if self._password_hash is not None:
                    await self.users.bootstrap(self._username,self._password_hash.decode())
                if not await self.users.db.pool.fetchval("SELECT EXISTS(SELECT 1 FROM user_accounts WHERE enabled AND role='admin')"):
                    raise ValueError('An active managed administrator is required')

    async def authenticate_async(self, username, password):
        if not self.multi_user:
            return await asyncio.to_thread(self.authenticate,username,password)
        try:
            async with asyncio.timeout(5):
                account=await self.users.authenticate(username,password)
        except (TimeoutError,asyncpg.PostgresError,asyncpg.InterfaceError) as error:
            raise AuthStateUnavailable() from error
        if account is None:return None
        return self.issue_account_token(account)

    def issue_account_token(self, account):
        """검증을 마친 활성 DB 계정의 현재 역할·버전으로 토큰을 발급한다."""
        if not self.multi_user or not account['enabled']:
            raise ValueError('An active managed account is required')
        now=datetime.now(timezone.utc)
        return jwt.encode({'sub':account['username'],'uid':account['id'],'ver':account['version'],
            'role':account['role'],'iat':now,'exp':now+timedelta(hours=self._expire_hours)},self._secret,algorithm='HS256')

    async def verify_token_async(self, token):
        payload=self._decode_token(token)
        if payload is None or not self.multi_user:return payload
        if type(payload.get('ver')) is not int or not isinstance(payload.get('uid'),str):return None
        try:
            async with asyncio.timeout(2):
                account=await self.users.get(payload['uid'])
        except (ValueError,TypeError):return None
        except (TimeoutError,asyncpg.PostgresError,asyncpg.InterfaceError) as error:
            raise AuthStateUnavailable() from error
        if (account is None or not account['enabled'] or account['version']!=payload['ver']
                or account['role']!=payload.get('role') or account['username']!=payload.get('sub')):return None
        return payload

    def verify_token(self, token: str) -> dict | None:
        # DB 확인 없는 경로는 관리 계정 토큰을 승인하지 않는다.
        return None if self.multi_user else self._decode_token(token)

    def _decode_token(self, token: str) -> dict | None:
        """JWT 토큰을 디코딩하고 유효성을 검증한다. 유효하면 payload dict 반환, 실패 시 None."""
        try:
            options = {"require": ["exp", "iat", "sub", "uid", "ver", "role"]} if self.multi_user else None
            return jwt.decode(token, self._secret, algorithms=["HS256"], options=options)
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
        if path.startswith("/ws/") or path.startswith("/api/ws/"):
            return await call_next(request)

        # /api/* 경로만 인증 필요
        if path.startswith("/api/"):
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return await self._deny(request, "Missing or invalid Authorization header")
            token = auth_header[7:]
            try:
                payload = await self._auth.verify_token_async(token)
            except AuthStateUnavailable:
                return JSONResponse({'error':'Account verification unavailable'},status_code=503)
            if not payload:
                return await self._deny(request, "Invalid or expired token")
            request.state.user = payload

        return await call_next(request)

    async def _deny(self, request: Request, message: str):
        limiter = getattr(request.app.state, "api_limiter", None)
        if limiter is not None:
            from netwatcher.web.api_rate_limiter import request_key
            if not await limiter.check(request_key(request)):
                return JSONResponse({"error": "Too many requests"}, status_code=429,
                    headers={"Retry-After": "60"})
        audit = getattr(request.app.state, "audit_logger", None)
        if audit is not None:
            try:
                async with asyncio.timeout(2):
                    await audit.log(user="anonymous", action="access_denied",
                        resource=request.url.path,
                        details={"method": request.method, "status": 401},
                        ip=request.client.host if request.client else "")
            except Exception:
                logger.warning("Authentication denial audit unavailable")
        return JSONResponse({"error": message}, status_code=401)
