"""프로토콜 이상 탐지: TTL 조작, 비정상 플래그 조합, IP 스푸핑 징후."""

from __future__ import annotations

import logging
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.protocol_anomaly")


class ProtocolAnomalyEngine(DetectionEngine):
    """표준 프로토콜 사양을 벗어나는 패킷을 탐지한다.

    - TTL Tampering: 패킷의 TTL 값이 비정상적으로 낮거나 변조됨 (우회 시도)
    - Bogus TCP Flags: TCP 핸드셰이크 사양에 어긋나는 플래그 조합
    - Reserved Bits: IP/TCP 헤더의 예약된 비트가 설정됨
    """

    name = "protocol_anomaly"
    description = "프로토콜 사양을 벗어나는 패킷을 탐지합니다. TTL 변조, 비정상 TCP 플래그 등 회피 공격 시도를 식별합니다."
    description_key = "engines.protocol_anomaly.description"
    config_schema = {
        "min_ttl": {
            "type": int, "default": 10, "min": 1, "max": 64,
            "label": "최소 TTL",
            "label_key": "engines.protocol_anomaly.min_ttl.label",
            "description": "패킷의 TTL이 이 값보다 작으면 변조된 패킷으로 의심. "
                           "일반적인 내부망 패킷은 64, 128, 255에서 시작.",
            "description_key": "engines.protocol_anomaly.min_ttl.description",
        },
        "detect_reserved_bits": {
            "type": bool, "default": True,
            "label": "예약 비트 검사",
            "label_key": "engines.protocol_anomaly.detect_reserved_bits.label",
            "description": "IP/TCP 헤더의 예약된(Reserved) 비트가 설정된 경우 탐지.",
            "description_key": "engines.protocol_anomaly.detect_reserved_bits.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._min_ttl = config.get("min_ttl", 10)
        self._detect_reserved = config.get("detect_reserved_bits", True)
        self._alerted_ips: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """IP 및 TCP 헤더의 이상 징후를 분석한다."""
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        ttl = packet[IP].ttl

        # 1. TTL Tampering 검사
        if ttl < self._min_ttl:
            if src_ip not in self._alerted_ips:
                self._alerted_ips.add(src_ip)
                return Alert(
                    engine=self.name,
                    severity=Severity.WARNING,
                    title="Low TTL Detected (Possible Tampering)",
                    title_key="engines.protocol_anomaly.alerts.low_ttl.title",
                    description=(
                        f"Packet from {src_ip} has an unusually low TTL ({ttl}). "
                        "May indicate routing manipulation or evasion attempts."
                    ),
                    description_key="engines.protocol_anomaly.alerts.low_ttl.description",
                    source_ip=src_ip,
                    confidence=0.6,
                    metadata={"ttl": ttl},
                )

        # 2. 비정상 TCP 플래그 검사 (예: SYN+FIN)
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            # SYN(S)와 FIN(F)이 동시에 설정된 경우 (0x03)
            if "S" in str(flags) and "F" in str(flags):
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Bogus TCP Flags (SYN+FIN)",
                    title_key="engines.protocol_anomaly.alerts.bogus_flags.title",
                    description=(
                        f"TCP packet from {src_ip} has SYN and FIN flags set simultaneously. "
                        "This is an illegal state used to bypass firewalls or for fingerprinting."
                    ),
                    description_key="engines.protocol_anomaly.alerts.bogus_flags.description",
                    source_ip=src_ip,
                    confidence=0.9,
                    metadata={"flags": str(flags)},
                )

        # 3. Reserved Bits 검사 (IP)
        if self._detect_reserved:
            # IP의 Reserved Bit는 0x8000 (Scapy flags 필드에서 'evil' 비트)
            if packet[IP].flags == 0x04:  # Reserved flag
                return Alert(
                    engine=self.name,
                    severity=Severity.INFO,
                    title="IP Reserved Bit Set",
                    title_key="engines.protocol_anomaly.alerts.reserved_bit.title",
                    description=(
                        f"Packet from {src_ip} has the IP reserved (evil) bit set. "
                        "Often used by specialized scanners or malware."
                    ),
                    description_key="engines.protocol_anomaly.alerts.reserved_bit.description",
                    source_ip=src_ip,
                    confidence=0.5,
                )

        return None

    def shutdown(self) -> None:
        """엔진 데이터를 초기화한다."""
        self._alerted_ips.clear()
