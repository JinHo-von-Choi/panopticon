"""DHCP 스푸핑 탐지: 비인가 DHCP 서버, DHCP 고갈 공격."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import BOOTP, DHCP, IP, UDP, Ether, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.engines.dhcp_spoof")

# DHCP 메시지 타입
_DHCP_DISCOVER = 1
_DHCP_OFFER = 2
_DHCP_REQUEST = 3
_DHCP_ACK = 5


def _get_dhcp_type(packet: Packet) -> int | None:
    """옵션에서 DHCP 메시지 타입을 추출한다."""
    if not packet.haslayer(DHCP):
        return None
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and option[0] == "message-type":
            return option[1]
    return None


class DHCPSpoofEngine(DetectionEngine):
    """DHCP 기반 공격을 탐지한다.

    - 비인가 DHCP 서버: 정상 서버 학습 후 새로운 DHCP OFFER/ACK 출처 탐지
    - DHCP 고갈: 다양한 MAC에서 다수의 DISCOVER 패킷 (MAC 플러딩)
    """

    name = "dhcp_spoof"
    description = "비인가 DHCP 서버를 탐지합니다. 공격자가 위조 DHCP 응답으로 네트워크 설정을 조작하는 것을 방지합니다."
    description_key = "engines.dhcp_spoof.description"
    config_schema = {
        "starvation_threshold": {
            "type": int, "default": 50, "min": 5, "max": 1000,
            "label": "DHCP Starvation 임계값",
            "label_key": "engines.dhcp_spoof.starvation_threshold.label",
            "description": "윈도우 내 DHCP DISCOVER 패킷 수가 이 값을 초과하면 "
                           "DHCP 고갈 공격(Starvation) 알림 발생. "
                           "공격자가 모든 IP를 소진시키려는 시도 탐지.",
            "description_key": "engines.dhcp_spoof.starvation_threshold.description",
        },
        "starvation_window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "Starvation 윈도우(초)",
            "label_key": "engines.dhcp_spoof.starvation_window_seconds.label",
            "description": "DHCP Starvation 활동을 집계하는 시간 윈도우.",
            "description_key": "engines.dhcp_spoof.starvation_window_seconds.description",
        },
        "known_servers": {
            "type": list, "default": [],
            "label": "정상 DHCP 서버 IP 목록",
            "label_key": "engines.dhcp_spoof.known_servers.label",
            "description": "정상 DHCP 서버의 IP 주소 목록 (쉼표 구분). "
                           "비어있으면 처음 관측된 서버를 자동 학습. "
                           "목록에 없는 서버가 DHCP OFFER를 보내면 Rogue DHCP 알림.",
            "description_key": "engines.dhcp_spoof.known_servers.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """DHCP 스푸핑 엔진을 초기화한다. Starvation 임계값과 정상 서버 목록을 설정한다."""
        super().__init__(config)
        self._starvation_threshold = config.get("starvation_threshold", 50)
        self._starvation_window = config.get("starvation_window_seconds", 60)

        # 사전 정의된 DHCP 서버 또는 자동 학습
        predefined = config.get("known_servers", [])
        self._known_servers: set[str] = set(predefined)
        self._auto_learn = len(predefined) == 0
        self._rogue_alerted: set[str] = set()

        # DHCP 고갈 추적: deque of (timestamp, src_mac)
        self._discover_timestamps: deque[tuple[float, str]] = deque()
        self._starvation_alerted: float = 0.0

    def analyze(self, packet: Packet) -> Alert | None:
        """DHCP 패킷에서 비인가 서버와 고갈 공격을 탐지한다."""
        dhcp_type = _get_dhcp_type(packet)
        if dhcp_type is None:
            return None

        src_ip = packet[IP].src if packet.haslayer(IP) else None
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None

        # 비인가 DHCP 서버 탐지 (알 수 없는 서버의 OFFER 또는 ACK)
        if dhcp_type in (_DHCP_OFFER, _DHCP_ACK) and src_ip:
            if self._auto_learn and not self._known_servers:
                # 사전 정의 없음 — 첫 서버를 정상으로 학습
                self._known_servers.add(src_ip)
                logger.info("Auto-learned DHCP server: %s", src_ip)
                return None

            if src_ip not in self._known_servers and src_ip not in self._rogue_alerted:
                self._rogue_alerted.add(src_ip)
                msg_type = "OFFER" if dhcp_type == _DHCP_OFFER else "ACK"
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Rogue DHCP Server Detected",
                    title_key="engines.dhcp_spoof.alerts.rogue_server.title",
                    description=(
                        f"DHCP {msg_type} from unknown server {src_ip} "
                        f"(MAC: {src_mac}). Known servers: "
                        f"{', '.join(self._known_servers)}. "
                        "This may be a rogue DHCP server attack."
                    ),
                    description_key="engines.dhcp_spoof.alerts.rogue_server.description",
                    source_ip=src_ip,
                    source_mac=src_mac,
                    confidence=0.9,
                    metadata={
                        "dhcp_type": msg_type,
                        "known_servers": list(self._known_servers),
                        "known_servers_str": ", ".join(self._known_servers),
                    },
                )

        # DHCP 고갈 탐지 (다양한 MAC에서 다수의 DISCOVER)
        if dhcp_type == _DHCP_DISCOVER and src_mac:
            now = time.time()
            self._discover_timestamps.append((now, src_mac))

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """DHCP Starvation 공격 여부를 주기적으로 검사한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._starvation_window

        # 오래된 DISCOVER 항목 제거
        while self._discover_timestamps and self._discover_timestamps[0][0] < cutoff:
            self._discover_timestamps.popleft()

        # 고갈 검사: DISCOVER를 보내는 다수의 고유 MAC
        unique_macs = set(mac for _, mac in self._discover_timestamps)
        if (
            len(unique_macs) >= self._starvation_threshold
            and now - self._starvation_alerted > self._starvation_window
        ):
            self._starvation_alerted = now
            alerts.append(Alert(
                engine=self.name,
                severity=Severity.CRITICAL,
                title="DHCP Starvation Attack Detected",
                title_key="engines.dhcp_spoof.alerts.starvation.title",
                description=(
                    f"{len(unique_macs)} unique MAC addresses sent DHCP DISCOVER "
                    f"in {self._starvation_window}s. Possible DHCP starvation attack."
                ),
                description_key="engines.dhcp_spoof.alerts.starvation.description",
                confidence=0.8,
                metadata={
                    "unique_macs": len(unique_macs),
                    "count": len(unique_macs),
                    "window_seconds": self._starvation_window,
                    "sample_macs": sorted(unique_macs)[:10],
                },
            ))

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._known_servers.clear()
        self._rogue_alerted.clear()
        self._discover_timestamps.clear()
        self._starvation_alerted = 0.0
