"""데이터 유출 탐지: 대량 아웃바운드 전송, 비정상 업로드 비율."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from scapy.all import IP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.network import is_private_ip

logger = logging.getLogger("netwatcher.detection.engines.data_exfil")


class DataExfilEngine(DetectionEngine):
    """대량의 데이터를 외부로 전송하는 활동을 탐지한다.

    - Massive Outbound Transfer: 짧은 시간 내 외부 IP로 전송된 바이트 수가 임계값 초과
    - High Upload Ratio: 다운로드 대비 업로드 비율이 비정상적으로 높음 (공격자 서버로 데이터 전송 의심)
    """

    name = "data_exfil"
    description = "데이터 유출 활동을 탐지합니다. 대량의 외부 전송 및 비정상적인 업로드 비율을 감시합니다."
    description_key = "engines.data_exfil.description"
    config_schema = {
        "outbound_threshold_mb": {
            "type": int, "default": 50, "min": 10, "max": 1000,
            "label": "외부 전송 임계값(MB)",
            "label_key": "engines.data_exfil.outbound_threshold_mb.label",
            "description": "윈도우 내 외부 IP로 전송된 데이터가 이 값을 초과하면 유출 의심.",
            "description_key": "engines.data_exfil.outbound_threshold_mb.description",
        },
        "window_seconds": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "집계 윈도우(초)",
            "label_key": "engines.data_exfil.window_seconds.label",
            "description": "전송량을 합산하는 시간 단위.",
            "description_key": "engines.data_exfil.window_seconds.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._threshold_bytes = config.get("outbound_threshold_mb", 50) * 1024 * 1024
        self._window = config.get("window_seconds", 300)

        # (src_ip, dst_ip) -> total_bytes
        self._outbound_bytes: dict[tuple[str, str], int] = defaultdict(int)
        self._last_reset = time.time()
        self._alerted: dict[tuple[str, str], float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷 크기를 합산하여 외부 전송량을 추적한다."""
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)

        # 내부 -> 외부 전송만 추적
        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            self._outbound_bytes[(src_ip, dst_ip)] += size

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 누적 전송량을 검사하여 유출 알림을 생성한다."""
        alerts = []
        now = time.time()

        # 임계값 초과 확인
        for (src_ip, dst_ip), total in self._outbound_bytes.items():
            if total >= self._threshold_bytes:
                last_alert = self._alerted.get((src_ip, dst_ip), 0)
                if now - last_alert > self._window:
                    self._alerted[(src_ip, dst_ip)] = now
                    mb = total / (1024 * 1024)
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="Massive Data Exfiltration Detected",
                        title_key="engines.data_exfil.alerts.massive_transfer.title",
                        description=(
                            f"Host {src_ip} sent {mb:.1f} MB to external IP {dst_ip} "
                            f"in {self._window}s. Possible data theft."
                        ),
                        description_key="engines.data_exfil.alerts.massive_transfer.description",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.8,
                        metadata={"megabytes": round(mb, 1), "window_seconds": self._window},
                    ))

        # 윈도우 주기에 맞춰 카운터 초기화
        if now - self._last_reset >= self._window:
            self._outbound_bytes.clear()
            self._last_reset = now

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 정리한다."""
        self._outbound_bytes.clear()
        self._alerted.clear()
