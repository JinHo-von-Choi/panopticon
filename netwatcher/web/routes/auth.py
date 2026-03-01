"""인증 라우트 (JWT 로그인 / 상태 확인).

작성자: 최진호
작성일: 2026-03-01
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from netwatcher.web.auth import AuthManager


class LoginRequest(BaseModel):
    username: str
    password: str


def create_auth_router(auth_manager: "AuthManager") -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/login")
    async def login(body: LoginRequest):
        token = auth_manager.authenticate(body.username, body.password)
        if token is None:
            return JSONResponse({"error": "Invalid credentials"}, status_code=401)
        return {"token": token}

    @router.get("/status")
    async def status(request: Request):
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "Missing token"}, status_code=401)
        payload = auth_manager.verify_token(auth_header[7:])
        if payload is None:
            return JSONResponse({"error": "Invalid or expired token"}, status_code=401)
        return {"authenticated": True, "user": payload.get("sub")}

    return router
