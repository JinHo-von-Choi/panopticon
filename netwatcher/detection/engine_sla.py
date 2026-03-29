"""엔진별 SLA 모니터 및 서킷 브레이커.

각 탐지 엔진의 레이턴시를 추적하고, SLA 위반이 반복되면
서킷 브레이커를 열어 해당 엔진을 일시적으로 비활성화한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import statistics
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class EngineStats:
    """단일 엔진의 성능 통계."""

    call_count: int = 0
    total_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    consecutive_breaches: int = 0
    circuit_open_until: float = 0.0
    _latencies: deque[float] = field(default_factory=lambda: deque(maxlen=100))

    def percentile(self, p: int) -> float:
        """최근 레이턴시에서 p-백분위수를 계산한다. 데이터가 없으면 0.0."""
        if not self._latencies:
            return 0.0
        sorted_lat = sorted(self._latencies)
        idx = int(len(sorted_lat) * p / 100)
        idx = min(idx, len(sorted_lat) - 1)
        return sorted_lat[idx]


class EngineSLAMonitor:
    """엔진별 레이턴시를 추적하고 서킷 브레이커 패턴을 구현한다.

    Args:
        sla_ms: 엔진 분석 목표 레이턴시(밀리초). 이를 초과하면 SLA 위반.
        breach_threshold: 연속 SLA 위반 횟수 임계값. 초과 시 서킷 브레이커 오픈.
        cooldown_seconds: 서킷 브레이커 오픈 후 재시도까지 대기 시간(초).
    """

    def __init__(
        self,
        sla_ms: float = 10.0,
        breach_threshold: int = 10,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self._sla_ms           = sla_ms
        self._breach_threshold = breach_threshold
        self._cooldown_seconds = cooldown_seconds
        self._stats: dict[str, EngineStats] = {}

    def record(self, engine_name: str, latency_ms: float, success: bool) -> None:
        """엔진 호출 결과를 기록한다.

        Args:
            engine_name: 엔진 이름.
            latency_ms: 호출 소요 시간(밀리초).
            success: 예외 없이 완료되었는지 여부.
        """
        stats = self._stats.setdefault(engine_name, EngineStats())
        stats.call_count += 1
        stats.total_latency_ms += latency_ms
        stats.max_latency_ms = max(stats.max_latency_ms, latency_ms)
        stats._latencies.append(latency_ms)

        if success:
            stats.success_count += 1
        else:
            stats.failure_count += 1

        if latency_ms > self._sla_ms or not success:
            stats.consecutive_breaches += 1
            if stats.consecutive_breaches >= self._breach_threshold:
                stats.circuit_open_until = time.monotonic() + self._cooldown_seconds
        else:
            stats.consecutive_breaches = 0

    def is_circuit_open(self, engine_name: str) -> bool:
        """서킷 브레이커가 열려 있는지 확인한다.

        쿨다운이 만료되면 서킷을 닫고(half-open -> closed) False를 반환한다.
        """
        stats = self._stats.get(engine_name)
        if stats is None:
            return False
        if stats.circuit_open_until <= 0.0:
            return False
        now = time.monotonic()
        if now >= stats.circuit_open_until:
            # 쿨다운 만료: 서킷 리셋 (half-open -> closed)
            stats.circuit_open_until = 0.0
            stats.consecutive_breaches = 0
            return False
        return True

    def get_stats(self, engine_name: str) -> dict:
        """단일 엔진의 통계를 딕셔너리로 반환한다."""
        stats = self._stats.get(engine_name)
        if stats is None:
            return {}
        avg = stats.total_latency_ms / stats.call_count if stats.call_count else 0.0
        return {
            "call_count":           stats.call_count,
            "total_latency_ms":     stats.total_latency_ms,
            "avg_latency_ms":       round(avg, 3),
            "max_latency_ms":       stats.max_latency_ms,
            "success_count":        stats.success_count,
            "failure_count":        stats.failure_count,
            "consecutive_breaches": stats.consecutive_breaches,
            "circuit_open":         self.is_circuit_open(engine_name),
            "p50_ms":               round(stats.percentile(50), 3),
            "p95_ms":               round(stats.percentile(95), 3),
            "p99_ms":               round(stats.percentile(99), 3),
        }

    def get_all_stats(self) -> dict[str, dict]:
        """모든 엔진의 통계를 반환한다."""
        return {name: self.get_stats(name) for name in self._stats}
