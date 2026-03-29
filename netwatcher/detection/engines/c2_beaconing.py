"""C2 비콘 탐지 엔진 — RITA 스타일 다중 지표 스코어링으로 주기적 콜백 트래픽을 탐지한다.

Score = w1*S_timing + w2*S_size + w3*S_skew + w4*S_madm + w5*S_fft

각 지표는 IAT 및 페이로드 크기의 통계적 규칙성을 분석하여
C2 비콘 패턴의 신뢰도를 종합적으로 판단한다.
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from typing import Any

from scapy.all import IP, TCP, UDP, Raw, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.eviction import BoundedDefaultDict, prune_empty_keys, prune_expired_entries
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.c2_beaconing")

# 외부 목적지에만 적용 — RFC 1918 내부 대역 제외
_RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")

# 기본 가중치
_W_TIMING = 0.30
_W_SIZE   = 0.15
_W_SKEW   = 0.15
_W_MADM   = 0.15
_W_FFT    = 0.25


def _is_internal(ip: str) -> bool:
    """IP가 RFC 1918 사설 대역인지 확인한다."""
    return ip.startswith(_RFC1918_PREFIXES) or ip.startswith("127.")


def _cv(values: list[float]) -> float:
    """분산 계수(CV = 표준편차 / 평균)를 반환한다.

    값이 1개 이하이거나 평균이 0이면 1.0 (완전 불규칙)을 반환한다.
    """
    if len(values) < 2:
        return 1.0
    mean = statistics.mean(values)
    if mean == 0.0:
        return 1.0
    stdev = statistics.stdev(values)
    return stdev / mean


def _score_cv(cv: float) -> float:
    """CV 값을 0~1 점수로 변환한다. CV가 낮을수록 높은 점수."""
    if cv < 0.1:
        return 1.0
    if cv < 0.3:
        return 0.7
    if cv < 0.5:
        return 0.3
    return 0.0


def score_timing(iats: list[float]) -> float:
    """S_timing: IAT의 분산 계수 기반 간격 규칙성 점수."""
    return _score_cv(_cv(iats))


def score_size(sizes: list[int]) -> float:
    """S_size: 페이로드 크기의 분산 계수 기반 일관성 점수."""
    if len(sizes) < 2:
        return 0.0
    float_sizes = [float(s) for s in sizes]
    return _score_cv(_cv(float_sizes))


def score_bowley_skew(iats: list[float]) -> float:
    """S_skew: IAT 분포의 Bowley 왜도(비대칭) 점수.

    Bowley = (Q3 + Q1 - 2*Q2) / (Q3 - Q1)
    |skew|가 작을수록 대칭적 → 비콘 가능성 높음.
    """
    if len(iats) < 4:
        return 0.0
    sorted_iats = sorted(iats)
    n = len(sorted_iats)
    q1 = sorted_iats[n // 4]
    q2 = sorted_iats[n // 2]
    q3 = sorted_iats[(3 * n) // 4]
    denom = q3 - q1
    if denom == 0.0:
        return 1.0  # 완벽하게 동일한 값 — 대칭
    skew = (q3 + q1 - 2.0 * q2) / denom
    abs_skew = abs(skew)
    if abs_skew < 0.1:
        return 1.0
    if abs_skew < 0.3:
        return 0.7
    if abs_skew < 0.5:
        return 0.3
    return 0.0


def score_madm(iats: list[float]) -> float:
    """S_madm: MAD(중앙절대편차) / 중앙값 비율 기반 점수.

    비율이 낮을수록 일정한 간격 → 높은 점수.
    """
    if len(iats) < 2:
        return 0.0
    med = statistics.median(iats)
    if med == 0.0:
        return 0.0
    deviations = [abs(x - med) for x in iats]
    mad = statistics.median(deviations)
    ratio = mad / med
    if ratio < 0.1:
        return 1.0
    if ratio < 0.3:
        return 0.7
    if ratio < 0.5:
        return 0.3
    return 0.0


def _pure_python_rfft_power(values: list[float]) -> list[float]:
    """순수 Python으로 실수 입력의 FFT 파워 스펙트럼을 계산한다.

    N개 입력에 대해 N//2+1개의 파워 값을 반환한다.
    O(N^2) DFT이지만 세션당 최대 200개이므로 실용적이다.
    """
    n = len(values)
    half = n // 2 + 1
    power = []
    for k in range(half):
        re = 0.0
        im = 0.0
        for t in range(n):
            angle = 2.0 * math.pi * k * t / n
            re += values[t] * math.cos(angle)
            im -= values[t] * math.sin(angle)
        power.append(re * re + im * im)
    return power


def score_fft(iats: list[float]) -> float:
    """S_fft: 지배 주파수 파워 / 전체 파워 비율.

    numpy.fft를 사용하며, 사용 불가 시 순수 Python DFT로 fallback한다.
    """
    if len(iats) < 4:
        return 0.0

    # 평균 제거 (DC 성분 제거)
    mean_val = statistics.mean(iats)
    centered = [x - mean_val for x in iats]

    try:
        import numpy as np
        arr = np.array(centered, dtype=np.float64)
        fft_vals = np.fft.rfft(arr)
        power = (np.abs(fft_vals) ** 2).tolist()
    except ImportError:
        power = _pure_python_rfft_power(centered)

    # DC 성분(index 0) 제외
    if len(power) < 2:
        return 0.0
    ac_power = power[1:]
    total = sum(ac_power)
    if total == 0.0:
        return 1.0  # 완벽히 일정한 신호 (모든 값 동일)
    dominant = max(ac_power)
    ratio = dominant / total

    if ratio > 0.5:
        return 1.0
    if ratio > 0.3:
        return 0.7
    if ratio > 0.1:
        return 0.3
    return 0.0


def composite_score(iats: list[float], sizes: list[int]) -> float:
    """RITA 스타일 복합 비콘 점수를 계산한다.

    Score = w1*S_timing + w2*S_size + w3*S_skew + w4*S_madm + w5*S_fft
    """
    s_timing = score_timing(iats)
    s_size   = score_size(sizes)
    s_skew   = score_bowley_skew(iats)
    s_madm   = score_madm(iats)
    s_fft    = score_fft(iats)

    return (
        _W_TIMING * s_timing
        + _W_SIZE * s_size
        + _W_SKEW * s_skew
        + _W_MADM * s_madm
        + _W_FFT  * s_fft
    )


class C2BeaconingEngine(DetectionEngine):
    """호스트-목적지 쌍의 패킷 도착 간격(IAT) 및 크기를 추적하여 비콘 패턴을 탐지한다.

    RITA 스타일 다중 지표 스코어링을 사용하며, 모든 탐지는 on_tick()에서 수행한다.
    analyze()는 데이터 수집만 담당한다.

    탐지 조건:
    - 동일 (src_ip, dst_ip, dst_port) 쌍에서 `min_connections` 이상의 IAT 샘플이 관찰되고
    - 평균 IAT가 `min_interval`~`max_interval` 범위 안에 있으며
    - 복합 점수가 `score_threshold` 이상일 때
    """

    name = "c2_beaconing"
    description = "주기적인 C2 비콘 콜백 패턴을 RITA 스타일 다중 지표 분석으로 탐지합니다."
    description_key = "engines.c2_beaconing.description"
    engine_type = "cpu"
    mitre_attack_ids = ["T1071", "T1571"]  # Application Layer Protocol / Non-Standard Port
    config_schema = {
        "cv_threshold": {
            "type": float, "default": 0.3, "min": 0.05, "max": 1.0,
            "label": "CV 임계값 (하위호환)",
            "description": "하위 호환용. score_threshold 사용을 권장.",
        },
        "score_threshold": {
            "type": float, "default": 0.7, "min": 0.1, "max": 1.0,
            "label": "복합 점수 임계값 (WARNING)",
            "description": "복합 점수가 이 값 이상이면 WARNING 알림 발생.",
        },
        "critical_threshold": {
            "type": float, "default": 0.85, "min": 0.5, "max": 1.0,
            "label": "복합 점수 임계값 (CRITICAL)",
            "description": "복합 점수가 이 값 이상이면 CRITICAL 알림 발생.",
        },
        "min_connections": {
            "type": int, "default": 8, "min": 4, "max": 100,
            "label": "최소 샘플 수",
            "description": "비콘 판정에 필요한 최소 패킷 간격 샘플 수.",
        },
        "min_interval": {
            "type": float, "default": 5.0, "min": 1.0, "max": 300.0,
            "label": "최소 비콘 주기(초)",
            "description": "평균 IAT가 이 값 이하면 비콘으로 보지 않음.",
        },
        "max_interval": {
            "type": float, "default": 3600.0, "min": 60.0, "max": 86400.0,
            "label": "최대 비콘 주기(초)",
            "description": "평균 IAT가 이 값 이상이면 비콘으로 보지 않음.",
        },
        "cooldown_seconds": {
            "type": int, "default": 3600, "min": 60, "max": 86400,
            "label": "쿨다운(초)",
            "description": "동일 페어에 대한 알림 재발생 억제 시간.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._score_threshold: float = config.get("score_threshold", 0.7)
        self._critical_threshold: float = config.get("critical_threshold", 0.85)
        self._min_connections: int = config.get("min_connections", 8)
        self._min_interval: float = config.get("min_interval", 5.0)
        self._max_interval: float = config.get("max_interval", 3600.0)
        self._cooldown: int = config.get("cooldown_seconds", 3600)

        # (src_ip, dst_ip, dst_port) -> {"last_ts": float, "iats": list[float], "sizes": list[int]}
        self._sessions: BoundedDefaultDict = BoundedDefaultDict(
            lambda: {"last_ts": 0.0, "iats": [], "sizes": []},
            max_keys=5000,
        )
        self._alerted: dict[tuple[str, str, int], float] = {}

    # ------------------------------------------------------------------
    # DetectionEngine 인터페이스
    # ------------------------------------------------------------------

    def analyze(self, packet: Packet) -> Alert | None:
        """TCP/UDP 패킷의 도착 시각과 페이로드 크기를 수집한다.

        탐지 로직은 on_tick()에서 수행하므로, 여기서는 데이터만 기록한다.
        """
        if not packet.haslayer(IP):
            return None

        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst

        # 내부 → 내부 트래픽은 제외 (C2는 대개 외부 서버와 통신)
        if _is_internal(dst_ip):
            return None

        dst_port = 0
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        else:
            return None  # TCP/UDP가 아니면 의미 없는 IAT

        key = (src_ip, dst_ip, dst_port)
        now = time.time()
        session = self._sessions[key]

        # 페이로드 크기 추출
        payload_size = len(packet[Raw].load) if packet.haslayer(Raw) else 0

        if session["last_ts"] == 0.0:
            # 첫 패킷 — 타임스탬프만 기록
            session["last_ts"] = now
            session["sizes"].append(payload_size)
            return None

        iat = now - session["last_ts"]
        session["last_ts"] = now
        session["iats"].append(iat)
        session["sizes"].append(payload_size)

        # 윈도우 초과 시 오래된 데이터 제거 (최대 200개 유지)
        if len(session["iats"]) > 200:
            session["iats"] = session["iats"][-200:]
        if len(session["sizes"]) > 201:
            session["sizes"] = session["sizes"][-201:]

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """세션 데이터를 평가하고 비콘 패턴 알림을 생성한다."""
        alerts: list[Alert] = []
        now = time.time()

        for key, session in list(self._sessions.items()):
            iats  = session["iats"]
            sizes = session["sizes"]

            if len(iats) < self._min_connections:
                continue

            mean_iat = statistics.mean(iats)
            if not (self._min_interval <= mean_iat <= self._max_interval):
                continue

            score = composite_score(iats, sizes)
            if score < self._score_threshold:
                continue

            # 쿨다운 확인
            if now - self._alerted.get(key, 0.0) < self._cooldown:
                continue
            self._alerted[key] = now

            src_ip, dst_ip, dst_port = key
            severity = Severity.CRITICAL if score >= self._critical_threshold else Severity.WARNING
            cv = _cv(iats)
            confidence = min(0.98, 0.5 + score * 0.48)

            alerts.append(Alert(
                engine=self.name,
                severity=severity,
                title="C2 Beaconing Detected",
                title_key="engines.c2_beaconing.alerts.beacon.title",
                description=(
                    f"{src_ip} → {dst_ip}:{dst_port} exhibits periodic beaconing "
                    f"(avg_iat={mean_iat:.1f}s, CV={cv:.3f}, score={score:.3f}). "
                    "Possible C2 callback or implant heartbeat."
                ),
                description_key="engines.c2_beaconing.alerts.beacon.description",
                source_ip=src_ip,
                dest_ip=dst_ip,
                confidence=confidence,
                metadata={
                    "dst_port": dst_port,
                    "avg_iat_seconds": round(mean_iat, 2),
                    "cv": round(cv, 4),
                    "composite_score": round(score, 4),
                    "sample_count": len(iats),
                },
            ))

        # 정리
        prune_empty_keys(self._sessions)
        prune_expired_entries(self._alerted, max_age=self._cooldown * 2)
        return alerts

    def export_state(self) -> dict | None:
        """C2 비콘 세션 추적 상태를 직렬화한다."""
        sessions = {}
        for key, session in self._sessions.items():
            # key는 (src_ip, dst_ip, dst_port) 튜플
            str_key = f"{key[0]}|{key[1]}|{key[2]}"
            sessions[str_key] = {
                "last_ts": session["last_ts"],
                "iats": session["iats"][-200:],
                "sizes": session["sizes"][-201:],
            }

        alerted = {}
        for key, ts in self._alerted.items():
            str_key = f"{key[0]}|{key[1]}|{key[2]}"
            alerted[str_key] = ts

        return {
            "sessions": sessions,
            "alerted": alerted,
        }

    def import_state(self, state: dict) -> None:
        """이전에 내보낸 C2 비콘 상태를 복원한다."""
        for str_key, data in state.get("sessions", {}).items():
            parts = str_key.split("|")
            if len(parts) != 3:
                continue
            key = (parts[0], parts[1], int(parts[2]))
            session = self._sessions[key]
            session["last_ts"] = float(data.get("last_ts", 0.0))
            session["iats"] = [float(v) for v in data.get("iats", [])]
            session["sizes"] = [int(v) for v in data.get("sizes", [])]

        for str_key, ts in state.get("alerted", {}).items():
            parts = str_key.split("|")
            if len(parts) != 3:
                continue
            key = (parts[0], parts[1], int(parts[2]))
            self._alerted[key] = float(ts)

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._sessions.clear()
        self._alerted.clear()
