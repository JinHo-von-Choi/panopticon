"""범용 주기성 탐지 모듈 -- FFT, 자기상관, 엔트로피 기반.

작성자: 최진호
작성일: 2026-03-13
"""

from __future__ import annotations

import math
from collections import Counter

# numpy 사용 가능 시 FFT 가속, 불가 시 pure-Python DFT fallback
try:
    import numpy as _np
    _HAS_NUMPY = True
except ImportError:
    _np = None  # type: ignore[assignment]
    _HAS_NUMPY = False


def fft_periodicity_score(values: list[float]) -> float:
    """IAT 시계열의 FFT 주기성 점수를 반환한다 (0.0~1.0).

    dominant frequency의 power / total power.
    값이 높을수록 강한 주기성.
    """
    n = len(values)
    if n < 4:
        return 0.0

    if _HAS_NUMPY:
        arr = _np.array(values, dtype=float)
        spectrum = _np.abs(_np.fft.rfft(arr - arr.mean()))
        if len(spectrum) < 2:
            return 0.0
        # DC 성분(index 0) 제외
        magnitudes = spectrum[1:]
        total = float(magnitudes.sum())
        if total == 0:
            return 0.0
        dominant = float(magnitudes.max())
        return min(1.0, dominant / total)

    # Pure-Python DFT (O(n^2) -- n은 보통 200 이하이므로 허용)
    mean_val = sum(values) / n
    centered = [v - mean_val for v in values]
    half = n // 2 + 1
    magnitudes = []
    for k in range(1, half):
        re = sum(centered[j] * math.cos(2 * math.pi * k * j / n) for j in range(n))
        im = sum(centered[j] * math.sin(2 * math.pi * k * j / n) for j in range(n))
        magnitudes.append(math.sqrt(re * re + im * im))

    if not magnitudes:
        return 0.0
    total = sum(magnitudes)
    if total == 0:
        return 0.0
    dominant = max(magnitudes)
    return min(1.0, dominant / total)


def fft_dominant_period(values: list[float], sample_interval: float = 1.0) -> float | None:
    """FFT에서 지배적인 주기(초)를 반환한다. 검출 불가 시 None."""
    n = len(values)
    if n < 4:
        return None

    mean_val = sum(values) / n
    centered = [v - mean_val for v in values]
    half = n // 2 + 1
    magnitudes = []
    for k in range(1, half):
        re = sum(centered[j] * math.cos(2 * math.pi * k * j / n) for j in range(n))
        im = sum(centered[j] * math.sin(2 * math.pi * k * j / n) for j in range(n))
        magnitudes.append(math.sqrt(re * re + im * im))

    if not magnitudes:
        return None
    peak_idx = max(range(len(magnitudes)), key=lambda i: magnitudes[i])
    freq = (peak_idx + 1) / (n * sample_interval)
    if freq == 0:
        return None
    return 1.0 / freq


def autocorrelation_score(values: list[float], max_lag: int | None = None) -> float:
    """시계열의 최대 자기상관 계수를 반환한다 (0.0~1.0).

    lag 1~max_lag 범위에서 가장 높은 자기상관 값.
    > 0.7이면 강한 주기적 패턴.
    """
    n = len(values)
    if n < 4:
        return 0.0

    if max_lag is None:
        max_lag = min(n // 2, 100)
    max_lag = max(1, min(max_lag, n - 2))

    mean_val = sum(values) / n
    var = sum((v - mean_val) ** 2 for v in values) / n
    if var == 0:
        return 1.0  # 완전 동일 값 = 완벽한 주기성

    best = 0.0
    for lag in range(1, max_lag + 1):
        cov = sum(
            (values[j] - mean_val) * (values[j + lag] - mean_val)
            for j in range(n - lag)
        ) / n
        corr = cov / var
        if corr > best:
            best = corr

    return max(0.0, min(1.0, best))


def iat_entropy(intervals: list[float], bins: int = 20) -> float:
    """IAT 분포의 Shannon 엔트로피를 반환한다.

    정규 트래픽의 IAT 엔트로피는 높고(무질서),
    비콘은 낮다(규칙적).

    반환값 범위: 0.0 (단일 값) ~ log2(bins) (균등 분포).
    """
    n = len(intervals)
    if n < 2:
        return 0.0

    min_v = min(intervals)
    max_v = max(intervals)
    if min_v == max_v:
        return 0.0  # 완전 규칙적

    bin_width = (max_v - min_v) / bins
    counts: Counter[int] = Counter()
    for v in intervals:
        idx = min(int((v - min_v) / bin_width), bins - 1)
        counts[idx] += 1

    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def score_from_fft(periodicity: float) -> float:
    """FFT 주기성 점수를 0~1 스코어로 변환한다."""
    if periodicity > 0.5:
        return 1.0
    if periodicity > 0.3:
        return 0.7
    if periodicity > 0.1:
        return 0.3
    return 0.0


def score_from_autocorr(corr: float) -> float:
    """자기상관 계수를 0~1 스코어로 변환한다."""
    if corr > 0.7:
        return 1.0
    if corr > 0.5:
        return 0.7
    if corr > 0.3:
        return 0.3
    return 0.0


def score_from_entropy(entropy: float, max_entropy: float = 4.0) -> float:
    """엔트로피가 낮을수록 높은 비콘 스코어를 반환한다."""
    if max_entropy <= 0:
        return 0.0
    normalized = entropy / max_entropy
    if normalized < 0.2:
        return 1.0
    if normalized < 0.4:
        return 0.7
    if normalized < 0.6:
        return 0.3
    return 0.0
