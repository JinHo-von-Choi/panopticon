"""인증 뒤 API 제한과 변경 감사 기록을 실행한다."""

import asyncio

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from netwatcher.web.api_rate_limiter import request_key


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
        admin_paths = ("/api/whitelist", "/api/rules", "/api/blocklist", "/api/devices", "/api/engines")
        admin_change = any(path == prefix or path.startswith(prefix + "/") for prefix in admin_paths)
        if mutation and payload and (role not in ("admin", "analyst") or (admin_change and role != "admin")):
            response = JSONResponse({"error": "Role is not authorized for this change"}, 403)
        else:
            response = await call_next(request)
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
                pass  # 실제 승인 전 필수 감사는 require_role에서 별도 확인한다.
        return response
