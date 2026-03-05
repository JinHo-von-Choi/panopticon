"""세그먼트 격리 위반 탐지 엔진."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, UDP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.segmentation import SegmentFlow, parse_flows, is_allowed

logger = logging.getLogger("netwatcher.detection.engines.segment_violation")


class SegmentViolationEngine(DetectionEngine):
    """설정된 네트워크 세그먼트 격리 정책을 위반하는 트래픽을 탐지한다.

    `engines.segment_violation.allowed_flows`에 허용 플로우 목록을 설정한다.
    목록이 비어 있으면 탐지가 비활성화된다.
    """

    name = "segment_violation"
    description = "설정된 네트워크 세그먼트 격리 정책을 위반하는 트래픽을 탐지합니다."
    description_key = "engines.segment_violation.description"
    mitre_attack_ids = ["T1599"]   # Network Boundary Bridging
    requires_span = True
    config_schema = {
        "cooldown_seconds": {
            "type": int, "default": 300, "min": 10, "max": 3600,
            "label": "쿨다운(초)",
            "description": "동일 (src, dst) 쌍에 대한 알림 재발생 억제 시간.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._cooldown: int = config.get("cooldown_seconds", 300)
        raw_flows: list[dict] = config.get("allowed_flows", [])
        self._flows: list[SegmentFlow] = parse_flows(raw_flows)
        # (src_ip, dst_ip) -> 마지막 알림 시각
        self._alerted: dict[tuple[str, str], float] = defaultdict(float)

        if self._flows:
            logger.info(
                "SegmentViolationEngine: %d allowed flow(s) loaded", len(self._flows)
            )
        else:
            logger.info("SegmentViolationEngine: no allowed_flows configured — detection disabled")

    def analyze(self, packet: Packet) -> Alert | None:
        """IP 패킷이 허용 플로우 목록에 없으면 Alert를 반환한다."""
        if not self._flows:
            return None
        if not packet.haslayer(IP):
            return None

        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst

        proto = "other"
        dport = 0
        if packet.haslayer(TCP):
            proto = "tcp"
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "udp"
            dport = packet[UDP].dport

        if is_allowed(self._flows, src_ip, dst_ip, dport, proto):
            return None

        # 쿨다운 확인
        key = (src_ip, dst_ip)
        now = time.time()
        if now - self._alerted[key] < self._cooldown:
            return None
        self._alerted[key] = now

        return Alert(
            engine=self.name,
            severity=Severity.WARNING,
            title="Segment Violation Detected",
            title_key="engines.segment_violation.alerts.violation.title",
            description=(
                f"{src_ip} → {dst_ip}:{dport}/{proto} violates network segmentation policy."
            ),
            description_key="engines.segment_violation.alerts.violation.description",
            source_ip=src_ip,
            dest_ip=dst_ip,
            confidence=0.75,
            metadata={"dst_port": dport, "proto": proto},
        )

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._alerted.clear()
