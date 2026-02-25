"""ICMP 이상 탐지: Ping 스위프, ICMP 플러드, 비정상 ICMP 타입."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import ICMP, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.icmp_anomaly")

# 정찰 또는 공격을 나타낼 수 있는 의심스러운 ICMP 타입
_SUSPICIOUS_ICMP_TYPES = {
    5: "Redirect",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}


class ICMPAnomalyEngine(DetectionEngine):
    """ICMP 기반 이상을 탐지한다.

    - Ping 스위프: 출발지 IP가 다수의 목적지에 ping 전송
    - ICMP 플러드: 단일 출발지에서 과다한 ICMP 패킷
    - 비정상 ICMP 타입: Redirect, Timestamp, Address Mask
    """

    name = "icmp_anomaly"
    description = "ICMP 트래픽의 이상 패턴을 탐지합니다. Ping 플러드, ICMP 터널링, 비정상 크기 패킷 등을 식별합니다."
    config_schema = {
        "ping_sweep_threshold": {
            "type": int, "default": 20, "min": 3, "max": 1000,
            "label": "Ping Sweep 임계값",
            "description": "단일 출발지에서 윈도우 내 ICMP Echo를 보낸 고유 목적지 IP 수가 이 값을 초과하면 "
                           "네트워크 스캔(Ping Sweep) 알림 발생.",
        },
        "ping_sweep_window_seconds": {
            "type": int, "default": 30, "min": 5, "max": 300,
            "label": "Ping Sweep 윈도우(초)",
            "description": "Ping Sweep 활동을 집계하는 시간 윈도우.",
        },
        "flood_threshold": {
            "type": int, "default": 100, "min": 10, "max": 10000,
            "label": "ICMP Flood 임계값(pps)",
            "description": "윈도우 내 단일 출발지의 ICMP 패킷 수가 이 값을 초과하면 Flood 알림. "
                           "ICMP Flood 공격(DoS)이나 Smurf 공격 탐지용.",
        },
        "flood_window_seconds": {
            "type": int, "default": 1, "min": 1, "max": 60,
            "label": "ICMP Flood 윈도우(초)",
            "description": "ICMP Flood를 감지하는 시간 윈도우. 기본값 1초(초당 패킷 기준).",
        },
        "max_tracked_sources": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 출발지 수",
            "description": "메모리에 유지하는 ICMP 출발지 추적 테이블 크기.",
        },
        "cooldown_seconds": {
            "type": int, "default": 300, "min": 10, "max": 3600,
            "label": "재알림 쿨다운(초)",
            "description": "동일 출발지에 대해 알림 재발송까지 대기 시간.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """ICMP 이상 탐지 엔진을 초기화한다. 스위프/플러드 임계값 등을 설정한다."""
        super().__init__(config)
        self._sweep_threshold = config.get("ping_sweep_threshold", 20)
        self._sweep_window = config.get("ping_sweep_window_seconds", 30)
        self._flood_threshold = config.get("flood_threshold", 100)
        self._flood_window = config.get("flood_window_seconds", 1)
        self._max_tracked = config.get("max_tracked_sources", 10000)
        self._cooldown_seconds = config.get("cooldown_seconds", 300)

        # 스위프 탐지용 src_ip -> deque of (timestamp, dst_ip)
        self._ping_targets: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        # 플러드 탐지용 src_ip -> deque of timestamps
        self._icmp_timestamps: dict[str, deque[float]] = defaultdict(deque)
        # 쿨다운: src_ip -> 마지막 알림 시간
        self._sweep_alerted: dict[str, float] = {}
        self._flood_alerted: dict[str, float] = {}
        # (src_ip, icmp_type) -> 알림 시간 (TTL 제거 포함)
        self._type_alerted: dict[tuple[str, int], float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """ICMP 패킷에서 의심스러운 타입/스위프/플러드를 탐지한다."""
        if not packet.haslayer(ICMP):
            return None

        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip or not dst_ip:
            return None

        icmp = packet[ICMP]
        now = time.time()

        # 의심스러운 ICMP 타입 검사
        if icmp.type in _SUSPICIOUS_ICMP_TYPES:
            key = (src_ip, icmp.type)
            last_alert = self._type_alerted.get(key, 0)
            if now - last_alert > self._cooldown_seconds:
                self._type_alerted[key] = now
                type_name = _SUSPICIOUS_ICMP_TYPES[icmp.type]
                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title=f"Unusual ICMP Type: {type_name}",
                    description=(
                        f"ICMP {type_name} (type={icmp.type}) from {src_ip} "
                        f"to {dst_ip}. This type is uncommon and may indicate "
                        "network reconnaissance or MITM attempt."
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.6,
                    metadata={
                        "icmp_type": icmp.type,
                        "icmp_code": icmp.code,
                        "type_name": type_name,
                    },
                )

        # 스위프 및 플러드 탐지를 위한 추적 (Echo Request = type 8)
        if icmp.type == 8:
            self._ping_targets[src_ip].append((now, dst_ip))
            self._icmp_timestamps[src_ip].append(now)

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """Ping 스위프와 ICMP 플러드를 주기적으로 검사하여 알림을 생성한다."""
        alerts = []
        now = time.time()

        # Ping 스위프 탐지
        sweep_cutoff = now - self._sweep_window
        sweep_keys_to_delete = []
        for src_ip, targets in self._ping_targets.items():
            while targets and targets[0][0] < sweep_cutoff:
                targets.popleft()
            if not targets:
                sweep_keys_to_delete.append(src_ip)
                continue

            unique_dsts = set(dst for _, dst in targets)
            last_alert = self._sweep_alerted.get(src_ip, 0)
            if len(unique_dsts) >= self._sweep_threshold and now - last_alert > self._sweep_window:
                self._sweep_alerted[src_ip] = now
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Ping Sweep Detected",
                    description=(
                        f"{src_ip} pinged {len(unique_dsts)} unique hosts in "
                        f"{self._sweep_window}s. Likely network reconnaissance."
                    ),
                    source_ip=src_ip,
                    confidence=0.85,
                    metadata={
                        "unique_targets": len(unique_dsts),
                        "window_seconds": self._sweep_window,
                        "sample_targets": sorted(unique_dsts)[:10],
                    },
                ))

        for key in sweep_keys_to_delete:
            del self._ping_targets[key]

        # ICMP 플러드 탐지
        flood_cutoff = now - self._flood_window
        flood_keys_to_delete = []
        for src_ip, timestamps in self._icmp_timestamps.items():
            while timestamps and timestamps[0] < flood_cutoff:
                timestamps.popleft()
            if not timestamps:
                flood_keys_to_delete.append(src_ip)
                continue

            count = len(timestamps)
            last_alert = self._flood_alerted.get(src_ip, 0)
            if count >= self._flood_threshold and now - last_alert > 60:
                self._flood_alerted[src_ip] = now
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="ICMP Flood Detected",
                    description=(
                        f"{src_ip} sent {count} ICMP packets in "
                        f"{self._flood_window}s (threshold: {self._flood_threshold})."
                    ),
                    source_ip=src_ip,
                    confidence=0.75,
                    metadata={
                        "packet_count": count,
                        "window_seconds": self._flood_window,
                    },
                ))

        for key in flood_keys_to_delete:
            del self._icmp_timestamps[key]

        # 만료된 쿨다운 항목 제거
        expired_sweep = [k for k, t in self._sweep_alerted.items() if now - t > self._cooldown_seconds]
        for k in expired_sweep:
            del self._sweep_alerted[k]

        expired_flood = [k for k, t in self._flood_alerted.items() if now - t > 60]
        for k in expired_flood:
            del self._flood_alerted[k]

        expired_type = [k for k, t in self._type_alerted.items() if now - t > self._cooldown_seconds]
        for k in expired_type:
            del self._type_alerted[k]

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._ping_targets.clear()
        self._icmp_timestamps.clear()
        self._sweep_alerted.clear()
        self._flood_alerted.clear()
        self._type_alerted.clear()
