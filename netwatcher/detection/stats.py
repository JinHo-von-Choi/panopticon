"""통계 기반 이상 탐지 유틸리티.

Adaptive EWMA, 주간 계절성 분해, MAD 기반 이상 탐지 클래스를 제공한다.
numpy 의존 없이 순수 Python + stdlib statistics 모듈만 사용한다.

작성자: 최진호
작성일: 2026-03-13
"""

from __future__ import annotations

import math
import statistics as _stats
from collections import deque


class AdaptiveEWMA:
    """적응적 분산 추적을 포함한 지수 가중 이동 평균.

    mu_t    = alpha * x_t + (1 - alpha) * mu_{t-1}
    sigma_t = sqrt(alpha * (x_t - mu_t)^2 + (1 - alpha) * sigma_{t-1}^2)
    z_score = (x_t - mu_t) / sigma_t   (sigma > 0 일 때)

    alpha = 2 / (span + 1)
    """

    __slots__ = ("_alpha", "_mu", "_sigma", "_count")

    def __init__(self, span: int = 30) -> None:
        self._alpha = 2.0 / (span + 1)
        self._mu    = 0.0
        self._sigma = 0.0
        self._count = 0

    def update(self, value: float) -> float:
        """새 값으로 갱신하고 z-score를 반환한다. 데이터 부족 시 0.0."""
        self._count += 1

        if self._count == 1:
            self._mu    = value
            self._sigma = 0.0
            return 0.0

        # 이전 mu/sigma 기준으로 z-score 산출 (갱신 전 기준이어야 스파이크 감도가 높다)
        prev_mu    = self._mu
        prev_sigma = self._sigma

        self._mu    = self._alpha * value + (1.0 - self._alpha) * prev_mu
        deviation_sq = (value - prev_mu) ** 2
        self._sigma = math.sqrt(
            self._alpha * deviation_sq + (1.0 - self._alpha) * prev_sigma ** 2
        )

        if not self.ready or prev_sigma <= 0.0:
            return 0.0

        return (value - prev_mu) / prev_sigma

    @property
    def ready(self) -> bool:
        """충분한 데이터가 수집되었는지 여부 (count >= 3)."""
        return self._count >= 3

    @property
    def mean(self) -> float:
        return self._mu

    @property
    def count(self) -> int:
        return self._count


class SeasonalBuffer:
    """168-슬롯 순환 버퍼로 주간 시간대별 패턴을 추적한다.

    각 슬롯은 해당 시간대(hour_of_week)에 관측된 값의 누적 평균을 저장한다.
    """

    _SLOTS = 168  # 7일 * 24시간

    __slots__ = ("_sums", "_counts", "_total_updates")

    def __init__(self) -> None:
        self._sums:   list[float] = [0.0] * self._SLOTS
        self._counts: list[int]   = [0]   * self._SLOTS
        self._total_updates       = 0

    def update(self, hour_of_week: int, value: float) -> None:
        """지정 슬롯에 값을 누적한다."""
        idx = hour_of_week % self._SLOTS
        self._sums[idx]   += value
        self._counts[idx] += 1
        self._total_updates += 1

    def get_factor(self, hour_of_week: int) -> float:
        """계절 보정 계수를 반환한다 (슬롯 평균 / 전역 평균). 데이터 부족 시 1.0."""
        if not self.ready:
            return 1.0

        idx = hour_of_week % self._SLOTS
        if self._counts[idx] == 0:
            return 1.0

        slot_mean = self._sums[idx] / self._counts[idx]

        total_sum = sum(self._sums)
        total_cnt = sum(self._counts)
        if total_cnt == 0:
            return 1.0
        global_mean = total_sum / total_cnt

        if global_mean <= 0.0:
            return 1.0

        return slot_mean / global_mean

    @property
    def ready(self) -> bool:
        """최소 1주일(168회 이상) 업데이트가 완료되었는지 여부."""
        return self._total_updates >= self._SLOTS


class MADDetector:
    """Median Absolute Deviation 기반 이상 탐지기.

    MAD        = median(|x_i - median(X)|)
    modified_z = 0.6745 * (x - median) / MAD

    슬라이딩 윈도우의 최근 값을 유지하며 로버스트 z-score를 산출한다.
    """

    _K = 0.6745  # MAD → 표준편차 변환 상수 (정규분포 가정)

    __slots__ = ("_window",)

    def __init__(self, window_size: int = 100) -> None:
        self._window: deque[float] = deque(maxlen=max(3, window_size))

    def update(self, value: float) -> float:
        """값을 추가하고 modified z-score를 반환한다. 데이터 부족 시 0.0."""
        self._window.append(value)

        if len(self._window) < 3:
            return 0.0

        data   = list(self._window)
        median = _stats.median(data)
        mad    = _stats.median(abs(x - median) for x in data)

        if mad <= 0.0:
            return 0.0

        return self._K * (value - median) / mad

    @property
    def window(self) -> deque[float]:
        """내부 윈도우 참조를 반환한다 (테스트용)."""
        return self._window
