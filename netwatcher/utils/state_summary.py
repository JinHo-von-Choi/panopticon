"""변경 상태를 감사 기록에 넣을 수 있는 요약으로 바꾼다.

비밀값이 감사 기록에 남으면 안 된다. 수치·불리언은 비교하고, 자유
문자열은 해시와 길이만 남긴다.

이 모듈은 웹 계층 밖에서도 쓴다 — 센서 프로세스는 FastAPI 를 끌어들이지
않아야 한다.
"""

from __future__ import annotations

import hashlib
import math

# 키 이름에 이 단어가 들어가면 값을 남기지 않는다.
SECRET_KEY_HINTS = (
    "password", "secret", "token", "credential", "authorization", "cookie", "key",
)


def state_summary(value, depth: int = 0):
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
        return {str(key): "[redacted]" if any(word in str(key).lower() for word in SECRET_KEY_HINTS)
                else state_summary(item, depth + 1) for key, item in list(value.items())[:64]}
    if isinstance(value, (list, tuple)):
        return [state_summary(item, depth + 1) for item in value[:64]]
    return {"omitted": "unsupported_type"}
