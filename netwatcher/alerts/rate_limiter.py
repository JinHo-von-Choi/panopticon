"""알림 중복 제거를 위한 슬라이딩 윈도우 속도 제한기."""

from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    """슬라이딩 윈도우 속도 제한기.

    window_seconds 내에서 키당 max_count 이벤트를 허용한다.
    메모리 고갈을 방지하기 위해 추적 키 총 수를 max_keys로 제한한다.
    """

    def __init__(
        self,
        window_seconds: int = 300,
        max_count: int = 5,
        max_keys: int = 10000,
    ) -> None:
        """윈도우 크기, 키당 최대 허용 수, 최대 추적 키 수를 설정한다."""
        self._window   = window_seconds
        self._max      = max_count
        self._max_keys = max_keys
        self._timestamps: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        """이벤트가 허용되어야 하면 (속도 제한되지 않으면) True를 반환한다."""
        now    = time.time()
        cutoff = now - self._window

        ts = self._timestamps[key]
        while ts and ts[0] < cutoff:
            ts.popleft()

        if len(ts) >= self._max:
            return False

        ts.append(now)
        return True

    def cleanup(self) -> None:
        """빈 키를 제거하고 max_keys 초과 시 오래된 절반을 삭제한다."""
        empty = [k for k, v in self._timestamps.items() if not v]
        for k in empty:
            del self._timestamps[k]

        if len(self._timestamps) > self._max_keys:
            oldest = sorted(
                self._timestamps,
                key=lambda k: self._timestamps[k][0] if self._timestamps[k] else 0,
            )
            for k in oldest[: len(oldest) // 2]:
                del self._timestamps[k]

    def reset(self, key: str | None = None) -> None:
        """특정 키 또는 모든 키의 속도 제한 상태를 초기화한다."""
        if key:
            self._timestamps.pop(key, None)
        else:
            self._timestamps.clear()
