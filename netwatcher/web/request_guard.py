"""인증 뒤 API 제한과 변경 감사 기록을 실행한다."""

import asyncio
import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from netwatcher.web.api_rate_limiter import request_key
from netwatcher.web.rbac import is_admin_change

logger = logging.getLogger(__name__)


class RequestGuard(BaseHTTPMiddleware):
    def __init__(self, app, limiter=None, audit_logger=None):
        super().__init__(app)
        self.limiter = limiter
        self.audit = audit_logger

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if not path.startswith("/api/") or path.startswith("/api/auth/"):
            return await call_next(request)
        key = request_key(request)
        if self.limiter is not None and not await self.limiter.check(key):
            return JSONResponse({"error": "Too many requests"}, 429, headers={"Retry-After": "60"})
        mutation = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        payload = getattr(request.state, "user", {})
        role = payload.get("role", "viewer")
        admin_change = is_admin_change(path, request.method)
        if mutation and payload and (role not in ("admin", "analyst") or (admin_change and role != "admin")):
            response = JSONResponse({"error": "Role is not authorized for this change"}, 403)
        else:
            try:
                response = await call_next(request)
            except Exception as exc:
                intent = getattr(request.state, "audit_intent", None)
                if intent is None:
                    raise
                logger.error("Change execution could not be confirmed: request=%s reason=%s",
                             intent["request_id"], type(exc).__name__)
                saved = await self._record_outcome(request, 500, "unknown")
                return JSONResponse({
                    "error": "Change result is unknown; reconcile before retrying",
                    "code": "change_execution_unknown" if saved else "audit_outcome_unavailable",
                    "execution_status": "unknown", "request_id": intent["request_id"],
                }, 500 if saved else 503, headers={"X-Request-ID": intent["request_id"]})
        intent = getattr(request.state, "audit_intent", None)
        if intent is not None:
            saved = await self._record_outcome(
                request, response.status_code,
                "unknown" if response.status_code >= 500 else
                "completed" if response.status_code < 400 else "failed",
            )
            if not saved:
                return JSONResponse({
                    "error": "Change result audit could not be saved; reconcile before retrying",
                    "code": "audit_outcome_unavailable", "execution_status": "unknown",
                    "request_id": intent["request_id"],
                }, 503)
            response.headers["X-Request-ID"] = intent["request_id"]
            return response
        if self.audit is not None and (mutation or response.status_code in {401, 403}):
            payload = getattr(request.state, "user", {})
            try:
                async with asyncio.timeout(2):
                    await self.audit.log(
                        user=str(payload.get("sub", "anonymous")),
                        action="api_mutation" if mutation else "access_denied",
                        resource=path,
                        details={"method": request.method, "status": response.status_code},
                        ip=request.client.host if request.client else "",
                    )
            except Exception:
                # 거절된 요청 등 부가 감사의 실패는 실행 성공으로 취급하지 않는다.
                logger.warning("Supplementary API audit unavailable")
        return response

    async def _record_outcome(self, request: Request, status: int, outcome: str) -> bool:
        intent = getattr(request.state, "audit_intent", None)
        if intent is None:
            return True
        try:
            audit = getattr(request.app.state, "audit_logger", self.audit)
            async with asyncio.timeout(2):
                return audit is not None and await audit.log(
                    user=intent["user"], action="api_mutation", resource=request.url.path,
                    details={"method": request.method, "status": status,
                             "outcome": outcome, "request_id": intent["request_id"],
                             **getattr(request.state, "audit_changes", {})},
                    ip=request.client.host if request.client else "",
                )
        except Exception:
            return False
