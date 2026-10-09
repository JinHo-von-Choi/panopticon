"""관리자 변경을 직렬화하고 변경 전후 상태를 감사 요청에 연결한다."""

import asyncio
import inspect
import hashlib
import math
from functools import wraps

from fastapi import HTTPException


def state_summary(value, depth=0):
    """수치·불리언은 비교하고 자유 문자열은 해시로만 보관한다."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"non_finite": str(value)}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return {"sha256": hashlib.sha256(value.encode()).hexdigest(), "length": len(value)}
    if depth >= 4:
        return {"omitted": "depth_limit"}
    if isinstance(value, dict):
        return {str(key): "[redacted]" if any(word in str(key).lower() for word in
                ("password", "secret", "token", "credential", "authorization", "cookie", "key"))
                else state_summary(item, depth + 1) for key, item in list(value.items())[:64]}
    if isinstance(value, (list, tuple)):
        return [state_summary(item, depth + 1) for item in value[:64]]
    return {"omitted": "unsupported_type"}


class ChangeAudit:
    def __init__(self):
        self._lock = asyncio.Lock()

    def guard(self, snapshot):
        """snapshot은 검증된 인자에서 비밀값 없는 상태 요약만 반환한다."""
        def decorate(handler):
            @wraps(handler)
            async def wrapped(*args, **kwargs):
                request = kwargs["request"]
                async with self._lock:
                    intent = getattr(request.state, "audit_intent", None)
                    if intent is None:
                        return await handler(*args, **kwargs)
                    async with asyncio.timeout(2):
                        before = snapshot(**kwargs)
                        if inspect.isawaitable(before):
                            before = await before
                    change = {"before": before, "after": None}
                    try:
                        async with asyncio.timeout(2):
                            saved = await request.app.state.audit_logger.log(
                                user=intent["user"], action="change_prepared",
                                resource=request.url.path,
                                details={"request_id": intent["request_id"], "method": request.method,
                                         "before": before},
                                ip=request.client.host if request.client else "",
                            )
                    except Exception:
                        saved = False
                    if not saved:
                        raise HTTPException(503, "Required change details audit is unavailable")
                    request.state.audit_changes = change
                    result = await handler(*args, **kwargs)
                    async with asyncio.timeout(2):
                        after = snapshot(**kwargs)
                        if inspect.isawaitable(after):
                            after = await after
                    change["after"] = after
                    return result

            # FastAPI은 래퍼 모듈에서 원래 모델의 지연 어노테이션을 해석할 수 없다.
            wrapped.__signature__ = inspect.signature(handler, eval_str=True)
            return wrapped
        return decorate
