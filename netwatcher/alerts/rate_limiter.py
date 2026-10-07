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
        self._next_cleanup = 0.0

    def allow(self, key: str) -> bool:
        """이벤트가 허용되어야 하면 (속도 제한되지 않으면) True를 반환한다."""
        now    = time.time()
        cutoff = now - self._window

        if key not in self._timestamps:
            if now >= self._next_cleanup:
                self.cleanup()
                self._next_cleanup = now + min(self._window, 1.0)
            if len(self._timestamps) >= self._max_keys:
                return False

        ts = self._timestamps[key]
        while ts and ts[0] < cutoff:
            ts.popleft()

        if len(ts) >= self._max:
            return False

        ts.append(now)
        return True

    def cleanup(self) -> None:
        """만료된 키만 제거한다. 활성 키의 제한을 초기화하지 않는다."""
        cutoff = time.time() - self._window
        empty = [k for k, v in self._timestamps.items() if not v or v[-1] < cutoff]
        for k in empty:
            del self._timestamps[k]

    def reset(self, key: str | None = None) -> None:
        """특정 키 또는 모든 키의 속도 제한 상태를 초기화한다."""
        if key:
            self._timestamps.pop(key, None)
        else:
            self._timestamps.clear()


class EventBudget:
    """전체 이벤트 저장 예산. 고위험 예약 몫은 일반 경보가 소비하지 않는다."""

    def __init__(self, normal: int = 120, critical_reserve: int = 30, clock=time.monotonic):
        self.normal = max(0, normal)
        self.reserve = max(0, critical_reserve)
        self._clock = clock
        self._normal: deque[float] = deque()
        self._reserved: deque[float] = deque()

    def allow(self, critical: bool = False) -> bool:
        now = self._clock()
        for timestamps in (self._normal, self._reserved):
            while timestamps and timestamps[0] <= now - 60:
                timestamps.popleft()
        if len(self._normal) < self.normal:
            self._normal.append(now)
            return True
        if critical and len(self._reserved) < self.reserve:
            self._reserved.append(now)
            return True
        return False
