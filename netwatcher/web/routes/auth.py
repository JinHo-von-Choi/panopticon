"""인증 라우트 (JWT 로그인 / 상태 확인).

작성자: 최진호
작성일: 2026-03-01
"""

from __future__ import annotations

from typing import TYPE_CHECKING
import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from netwatcher.web.auth import AuthManager


class LoginRequest(BaseModel):
    username: str
    password: str


def create_auth_router(auth_manager: "AuthManager | None") -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/login")
    async def login(body: LoginRequest, request: Request):
        if auth_manager is None or not auth_manager.enabled:
            return JSONResponse({"error": "Authentication is disabled"}, status_code=404)
        limiter = getattr(request.app.state, "login_limiter", None)
        ip = request.client.host if request.client else "unknown"
        if limiter is not None and not await limiter.check("login:" + ip):
            return JSONResponse({"error": "Too many login attempts"}, status_code=429,
                                headers={"Retry-After": "60"})
        token = await asyncio.to_thread(auth_manager.authenticate, body.username, body.password)
        if token is None:
            return JSONResponse({"error": "Invalid credentials"}, status_code=401)
        return {"token": token}

    @router.get("/status")
    async def status(request: Request):
        """인증 활성화 여부를 알린다. 토큰이 있으면 유효성까지 함께 검사한다.

        토큰 없이 호출할 수 있어야 대시보드가 로그인 화면 표시 여부를 판단할 수 있다.
        """
        enabled = auth_manager is not None and auth_manager.enabled
        if not enabled:
            return {"enabled": False}

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"enabled": True}

        payload = auth_manager.verify_token(auth_header[7:])
        if payload is None:
            return JSONResponse({"error": "Invalid or expired token"}, status_code=401)
        return {"enabled": True, "authenticated": True, "user": payload.get("sub"),
                "role": payload.get("role", "viewer")}

    return router
