"""ICMP 이상 탐지: Ping Sweep, ICMP Flood, 비정상 타입."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import ICMP, IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.icmp_anomaly")


class ICMPAnomalyEngine(DetectionEngine):
    """ICMP 트래픽의 이상 징후를 탐지한다.

    - Ping Sweep: 다수의 IP로 ICMP Echo Request 전송 (정찰 활동)
    - ICMP Flood: 단일 타겟에 대한 대량의 ICMP 패킷 전송 (DoS)
    - Suspicious Types: 잘 사용되지 않는 ICMP 타입 (데이터 터널링 의심)
    """

    name = "icmp_anomaly"
    description = "ICMP 트래픽의 이상을 탐지합니다. Ping Sweep, ICMP Flood, 잘 사용되지 않는 ICMP 타입 등을 감시합니다."
    description_key = "engines.icmp_anomaly.description"
    config_schema = {
        "sweep_threshold": {
            "type": int, "default": 10, "min": 3, "max": 50,
            "label": "Ping Sweep 임계값",
            "label_key": "engines.icmp_anomaly.sweep_threshold.label",
            "description": "윈도우 내 ICMP Echo Request를 받은 고유 IP 수가 이 값을 초과하면 Ping Sweep으로 판단.",
            "description_key": "engines.icmp_anomaly.sweep_threshold.description",
        },
        "flood_threshold": {
            "type": int, "default": 100, "min": 10, "max": 1000,
            "label": "ICMP Flood 임계값",
            "label_key": "engines.icmp_anomaly.flood_threshold.label",
            "description": "초당 ICMP 패킷 수가 이 값을 초과하면 ICMP Flood로 판단.",
            "description_key": "engines.icmp_anomaly.flood_threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "탐지 윈도우(초)",
            "label_key": "engines.icmp_anomaly.window_seconds.label",
            "description": "이상 활동을 집계하는 슬라이딩 윈도우 길이.",
            "description_key": "engines.icmp_anomaly.window_seconds.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화하고 ICMP 추적 버퍼를 생성한다."""
        super().__init__(config)
        self._sweep_threshold = config.get("sweep_threshold", 10)
        self._flood_threshold = config.get("flood_threshold", 100)
        self._window = config.get("window_seconds", 60)

        # src_ip -> deque of (timestamp, dst_ip)
        self._requests: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        # (src_ip, dst_ip) -> deque of timestamp
        self._floods: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """ICMP 패킷에서 정찰 활동 및 플러딩을 탐지한다."""
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        icmp_type = packet[ICMP].type
        now = time.time()

        # 비정상 ICMP 타입 탐지 (Echo, Redirect, Destination Unreachable 외)
        if icmp_type not in (0, 3, 5, 8, 11):
            if now - self._alerted.get(f"{src_ip}:type:{icmp_type}", 0) > self._window:
                self._alerted[f"{src_ip}:type:{icmp_type}"] = now
                return Alert(
                    engine=self.name,
                    severity=Severity.INFO,
                    title="Suspicious ICMP Type Detected",
                    title_key="engines.icmp_anomaly.alerts.suspicious_type.title",
                    description=(
                        f"Uncommon ICMP type {icmp_type} from {src_ip} to {dst_ip}. "
                        "May indicate covert channel or tunneling."
                    ),
                    description_key="engines.icmp_anomaly.alerts.suspicious_type.description",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=0.3,
                    metadata={"icmp_type": icmp_type},
                )

        # Ping Sweep 추적 (Echo Request만)
        if icmp_type == 8:
            self._requests[src_ip].append((now, dst_ip))

        # ICMP Flood 추적
        self._floods[(src_ip, dst_ip)].append(now)

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 Ping Sweep 및 Flood 여부를 검사한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        # Ping Sweep 검사
        for src_ip, targets in list(self._requests.items()):
            while targets and targets[0][0] < cutoff:
                targets.popleft()
            if not targets:
                continue

            unique_dsts = set(d for _, d in targets)
            if len(unique_dsts) >= self._sweep_threshold:
                if now - self._alerted.get(f"{src_ip}:sweep", 0) > self._window:
                    self._alerted[f"{src_ip}:sweep"] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Ping Sweep Detected",
                        title_key="engines.icmp_anomaly.alerts.sweep.title",
                        description=(
                            f"{src_ip} sent ICMP Echo Requests to {len(unique_dsts)} "
                            f"unique hosts in {self._window}s. Possible network scanning."
                        ),
                        description_key="engines.icmp_anomaly.alerts.sweep.description",
                        source_ip=src_ip,
                        confidence=0.7,
                        metadata={"unique_hosts": len(unique_dsts), "count": len(unique_dsts)},
                    ))

        # ICMP Flood 검사
        for (src_ip, dst_ip), times in list(self._floods.items()):
            # Flood는 더 짧은 윈도우(1초)로 평가
            flood_cutoff = now - 1.0
            while times and times[0] < flood_cutoff:
                times.popleft()
            if not times:
                continue

            if len(times) >= self._flood_threshold:
                if now - self._alerted.get(f"{src_ip}:flood:{dst_ip}", 0) > 10:
                    self._alerted[f"{src_ip}:flood:{dst_ip}"] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="ICMP Flood Detected",
                        title_key="engines.icmp_anomaly.alerts.flood.title",
                        description=(
                            f"High ICMP packet rate ({len(times)}/s) "
                            f"from {src_ip} to {dst_ip}. Possible DoS attack."
                        ),
                        description_key="engines.icmp_anomaly.alerts.flood.description",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.9,
                        metadata={"pps": len(times)},
                    ))

        return alerts

    def shutdown(self) -> None:
        """엔진 데이터를 초기화한다."""
        self._requests.clear()
        self._floods.clear()
        self._alerted.clear()
