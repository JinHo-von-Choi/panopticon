"""C2 비콘 탐지 엔진 — IAT 분산 계수(CV) 분석으로 주기적 콜백 트래픽을 탐지한다."""

from __future__ import annotations

import logging
import math
import statistics
import time
from netwatcher.detection.eviction import BoundedDefaultDict, prune_empty_keys, prune_expired_entries
from typing import Any

from scapy.all import IP, TCP, UDP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.c2_beaconing")

# 외부 목적지에만 적용 — RFC 1918 내부 대역 제외
_RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")


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


class C2BeaconingEngine(DetectionEngine):
    """호스트-목적지 쌍의 패킷 도착 간격(IAT)을 추적하여 비콘 패턴을 탐지한다.

    C2 악성코드는 일정한 주기로 서버에 콜백하므로 IAT의 CV가 낮다(≈0).
    정상 인간 발생 트래픽은 불규칙하여 CV가 높다.

    탐지 조건:
    - 동일 (src_ip, dst_ip, dst_port) 쌍에서 `min_connections` 이상의 패킷이 관찰되고
    - IAT의 CV가 `cv_threshold` 이하이며
    - 평균 IAT가 `min_interval`~`max_interval` 범위 안에 있을 때
    """

    name = "c2_beaconing"
    description = "주기적인 C2 비콘 콜백 패턴을 IAT 분산 계수 분석으로 탐지합니다."
    description_key = "engines.c2_beaconing.description"
    mitre_attack_ids = ["T1071", "T1571"]  # Application Layer Protocol / Non-Standard Port
    config_schema = {
        "cv_threshold": {
            "type": float, "default": 0.3, "min": 0.05, "max": 1.0,
            "label": "CV 임계값",
            "description": "분산 계수가 이 값 이하면 비콘으로 판단 (낮을수록 엄격).",
        },
        "min_connections": {
            "type": int, "default": 8, "min": 4, "max": 100,
            "label": "최소 샘플 수",
            "description": "비콘 판정에 필요한 최소 패킷 간격 샘플 수.",
        },
        "min_interval": {
            "type": float, "default": 5.0, "min": 1.0, "max": 300.0,
            "label": "최소 비콘 주기(초)",
            "description": "평균 IAT가 이 값 이하면 비콘으로 보지 않음 (너무 빠른 것은 다른 패턴).",
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
        self._cv_threshold: float = config.get("cv_threshold", 0.3)
        self._min_connections: int = config.get("min_connections", 8)
        self._min_interval: float = config.get("min_interval", 5.0)
        self._max_interval: float = config.get("max_interval", 3600.0)
        self._cooldown: int = config.get("cooldown_seconds", 3600)

        # (src_ip, dst_ip, dst_port) -> [last_ts, iat_1, iat_2, ...]
        self._sessions: BoundedDefaultDict = BoundedDefaultDict(list, max_keys=5000)
        self._alerted: dict[tuple[str, str, int], float] = {}

    # ------------------------------------------------------------------
    # DetectionEngine 인터페이스
    # ------------------------------------------------------------------

    def analyze(self, packet: Packet) -> Alert | None:
        """TCP/UDP 패킷 도착 시각을 기록하고 비콘 패턴을 평가한다."""
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

        if not session:
            # 첫 패킷 — 타임스탬프만 기록
            session.append(now)
            return None

        last_ts = session[0]
        iat = now - last_ts
        session[0] = now       # 마지막 패킷 시각 갱신
        session.append(iat)    # IAT 추가

        # 윈도우 초과 시 오래된 IAT 제거 (최대 200개 유지)
        if len(session) > 201:
            session[1:] = session[-200:]

        # IAT 샘플이 충분히 쌓이면 비콘 여부 판단
        iats = session[1:]  # index 0은 타임스탬프
        if len(iats) < self._min_connections:
            return None

        mean_iat = statistics.mean(iats)
        if not (self._min_interval <= mean_iat <= self._max_interval):
            return None

        cv = _cv(iats)
        if cv > self._cv_threshold:
            return None

        # 쿨다운 확인
        if now - self._alerted.get(key, 0.0) < self._cooldown:
            return None
        self._alerted[key] = now

        confidence = min(0.95, 0.65 + (1.0 - cv) * 0.3)
        return Alert(
            engine=self.name,
            severity=Severity.WARNING,
            title="C2 Beaconing Detected",
            title_key="engines.c2_beaconing.alerts.beacon.title",
            description=(
                f"{src_ip} → {dst_ip}:{dst_port} exhibits periodic beaconing "
                f"(avg_iat={mean_iat:.1f}s, CV={cv:.3f}). "
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
                "sample_count": len(iats),
            },
        )

    def on_tick(self, timestamp: float) -> list[Alert]:
        """세션/알림 데이터를 주기적으로 정리한다."""
        prune_empty_keys(self._sessions)
        prune_expired_entries(self._alerted, max_age=self._cooldown * 2)
        return []

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._sessions.clear()
        self._alerted.clear()
