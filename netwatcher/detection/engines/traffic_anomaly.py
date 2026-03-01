"""트래픽 양 이상 탐지: Z-score 기반 통계적 탐지, 신규 장치 탐지."""

from __future__ import annotations

import logging
import statistics
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.traffic_anomaly")


class TrafficAnomalyEngine(DetectionEngine):
    """네트워크 트래픽의 통계적 이상 징후를 탐지한다.

    - Volume Anomaly: 최근 트래픽 양이 평균에서 크게 벗어남 (Z-score 분석)
    - New Device: 네트워크에서 처음 관측된 MAC 주소 (인가되지 않은 장치)
    """

    name = "traffic_anomaly"
    description = "네트워크 트래픽 양의 통계적 이상 및 신규 장치의 등장을 탐지합니다."
    description_key = "engines.traffic_anomaly.description"
    config_schema = {
        "zscore_threshold": {
            "type": float, "default": 3.0, "min": 1.5, "max": 10.0,
            "label": "Z-score 임계값",
            "label_key": "engines.traffic_anomaly.zscore_threshold.label",
            "description": "트래픽 편차가 표준편차의 이 배수를 초과하면 이상으로 판단. "
                           "높을수록 보수적(확실한 이상만), 낮을수록 민감.",
            "description_key": "engines.traffic_anomaly.zscore_threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 300,
            "label": "집계 윈도우(초)",
            "label_key": "engines.traffic_anomaly.window_seconds.label",
            "description": "트래픽 양을 계산하는 시간 단위.",
            "description_key": "engines.traffic_anomaly.window_seconds.description",
        },
        "min_data_points": {
            "type": int, "default": 10, "min": 5, "max": 100,
            "label": "최소 데이터 포인트",
            "label_key": "engines.traffic_anomaly.min_data_points.label",
            "description": "Z-score를 계산하기 위한 최소한의 관측치 수.",
            "description_key": "engines.traffic_anomaly.min_data_points.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._z_threshold = config.get("zscore_threshold", 3.0)
        self._window = config.get("window_seconds", 60)
        self._min_points = config.get("min_data_points", 10)

        # 윈도우 내 현재 트래픽 카운터
        self._current_packets = 0
        self._current_bytes = 0
        self._last_window_end = time.time()

        # 과거 윈도우 기록 (packets)
        self._history: deque[int] = deque(maxlen=1440)  # 최대 24시간 분량 (1분 윈도우 기준)
        self._new_devices_alerted: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷을 카운팅하고 신규 장치를 탐지한다."""
        self._current_packets += 1
        self._current_bytes += len(packet)

        # 신규 장치 탐지 (등록된 장치가 아닌 경우)
        src_mac = getattr(packet, "src", None)
        if src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
            if self.whitelist and src_mac not in self._new_devices_alerted:
                # 화이트리스트(또는 Inventory)에 없는 장치인지 확인
                # 여기서는 단순함을 위해 첫 1회 관측 시 INFO 발생
                if not self.whitelist.is_whitelisted(source_mac=src_mac):
                    self._new_devices_alerted.add(src_mac)
                    src_ip = packet[IP].src if packet.haslayer(IP) else None
                    return Alert(
                        engine=self.name,
                        severity=Severity.INFO,
                        title="New Network Device Detected",
                        title_key="engines.traffic_anomaly.alerts.new_device.title",
                        description=(
                            f"A new device with MAC {src_mac} (IP: {src_ip or 'unknown'}) "
                            "was observed for the first time on the network."
                        ),
                        description_key="engines.traffic_anomaly.alerts.new_device.description",
                        source_ip=src_ip,
                        source_mac=src_mac,
                        confidence=0.5,
                        metadata={"mac": src_mac, "ip": src_ip},
                    )

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 트래픽 양을 평가하여 통계적 이상을 탐지한다."""
        alerts = []
        now = time.time()

        if now - self._last_window_end >= self._window:
            # 윈도우 종료 시점
            packets = self._current_packets
            self._current_packets = 0
            self._current_bytes = 0
            self._last_window_end = now

            if len(self._history) >= self._min_points:
                avg = statistics.mean(self._history)
                std = statistics.stdev(self._history)
                
                if std > 0:
                    z_score = (packets - avg) / std
                    if z_score > self._z_threshold:
                        alerts.append(Alert(
                            engine=self.name,
                            severity=Severity.WARNING,
                            title="Traffic Volume Anomaly Detected",
                            title_key="engines.traffic_anomaly.alerts.volume.title",
                            description=(
                                f"Traffic spike detected: {packets} packets in {self._window}s "
                                f"(Z-score: {z_score:.2f}, Avg: {avg:.1f})."
                            ),
                            description_key="engines.traffic_anomaly.alerts.volume.description",
                            confidence=0.7,
                            metadata={"packets": packets, "z_score": round(z_score, 2), "avg": round(avg, 1)},
                        ))
            
            self._history.append(packets)

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 정리한다."""
        self._history.clear()
        self._new_devices_alerted.clear()
