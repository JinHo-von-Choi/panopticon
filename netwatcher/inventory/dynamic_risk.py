"""동적 위험도 산정 모듈.

정적 risk_scorer의 결과를 실시간 알림 이력과 결합하여
호스트별 종합 위험 점수(0.0 ~ 10.0)를 산출한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any


# 심각도별 가중치
_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 4.0,
    "high":     3.0,
    "medium":   2.0,
    "warning":  1.5,
    "low":      1.0,
    "info":     0.5,
}

# 시간 감쇠 반감기(초) — 최근 알림일수록 가중치가 높음
_DECAY_HALF_LIFE = 3600.0  # 1시간

# 알림 다양성 보너스 — 여러 엔진에서 알림이 오면 가중
_DIVERSITY_BONUS_PER_ENGINE = 0.3

# 최대 이력 수 (호스트당)
_MAX_HISTORY = 100

# 동적 점수 최대값 (정적 점수와 합산 전)
_MAX_DYNAMIC_SCORE = 8.0


@dataclass(frozen=True)
class AlertRecord:
    """알림 이력 레코드."""

    timestamp: float
    severity:  str
    engine:    str


class DynamicRiskScorer:
    """정적 점수에 실시간 알림 기반 동적 요소를 결합하여 위험도를 산출한다.

    - record_alert(): 알림 발생 시 이력에 기록
    - calculate_risk(): 정적 점수 + 동적 점수 = 종합 점수 (0.0~10.0)
    - get_high_risk(): 임계값 이상인 호스트 목록
    """

    def __init__(self, decay_half_life: float = _DECAY_HALF_LIFE) -> None:
        self._alert_history: dict[str, deque[AlertRecord]] = defaultdict(
            lambda: deque(maxlen=_MAX_HISTORY),
        )
        self._decay_half_life = max(60.0, decay_half_life)

    def record_alert(self, ip: str, severity: str, engine: str) -> None:
        """알림 발생을 기록한다."""
        self._alert_history[ip].append(AlertRecord(
            timestamp = time.time(),
            severity  = severity.lower(),
            engine    = engine,
        ))

    def calculate_risk(self, ip: str, static_score: float = 0.0) -> float:
        """호스트의 종합 위험 점수를 산출한다 (0.0 ~ 10.0).

        구성:
          - static_score: risk_scorer.assess()의 결과(0~100)를 0~5 범위로 정규화
          - dynamic_score: 최근 알림의 시간 감쇠 가중합 + 엔진 다양성 보너스
        """
        # 정적 점수 정규화: 0~100 → 0~5
        static_norm = min(max(static_score, 0.0), 100.0) / 20.0

        # 동적 점수 계산
        history = self._alert_history.get(ip)
        if not history:
            return min(static_norm, 10.0)

        now           = time.time()
        weighted_sum  = 0.0
        engines_seen: set[str] = set()

        for record in history:
            age     = now - record.timestamp
            decay   = 0.5 ** (age / self._decay_half_life)
            weight  = _SEVERITY_WEIGHT.get(record.severity, 1.0)
            weighted_sum += weight * decay
            engines_seen.add(record.engine)

        # 엔진 다양성 보너스
        diversity_bonus = max(0, len(engines_seen) - 1) * _DIVERSITY_BONUS_PER_ENGINE

        dynamic_raw = weighted_sum + diversity_bonus
        # 로그 스케일 압축: 원시값을 0~_MAX_DYNAMIC_SCORE 범위로
        # 간단한 포화 함수: score = max * (1 - e^(-raw/scale))
        import math
        scale         = 5.0  # raw=5일 때 약 63%까지
        dynamic_score = _MAX_DYNAMIC_SCORE * (1.0 - math.exp(-dynamic_raw / scale))

        total = static_norm + dynamic_score
        return round(min(total, 10.0), 2)

    def get_high_risk(self, threshold: float = 7.0) -> list[dict[str, Any]]:
        """임계값 이상의 위험 점수를 가진 호스트 목록을 반환한다.

        Returns:
            [{"ip": ..., "risk_score": ..., "alert_count": ...}, ...]
        """
        result: list[dict[str, Any]] = []
        for ip, history in self._alert_history.items():
            score = self.calculate_risk(ip)
            if score >= threshold:
                result.append({
                    "ip":          ip,
                    "risk_score":  score,
                    "alert_count": len(history),
                })
        result.sort(key=lambda x: x["risk_score"], reverse=True)
        return result

    def get_risk_summary(self, ip: str) -> dict[str, Any]:
        """특정 호스트의 위험 요약 정보를 반환한다."""
        history = self._alert_history.get(ip)
        if not history:
            return {"ip": ip, "risk_score": 0.0, "alert_count": 0, "engines": []}

        engines = list({r.engine for r in history})
        return {
            "ip":          ip,
            "risk_score":  self.calculate_risk(ip),
            "alert_count": len(history),
            "engines":     engines,
        }
