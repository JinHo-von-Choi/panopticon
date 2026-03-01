"""랜섬웨어 측면 확산 탐지: SMB/RDP 브루트포스, 허니팟 접근."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, Packet, TCP

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.network import is_private_ip

logger = logging.getLogger("netwatcher.detection.engines.ransomware_lateral")


class RansomwareLateralEngine(DetectionEngine):
    """랜섬웨어가 네트워크를 통해 확산되는 과정에서 발생하는 패턴을 탐지한다.

    - SMB/RDP Brute Force: 특정 호스트로의 짧은 시간 내 대량의 연결 시도
    - Honeypot Access: 사용되지 않는 내부 IP/포트(허니팟)에 대한 접근 시도
    """

    name = "ransomware_lateral"
    description = "랜섬웨어의 측면 확산 활동을 탐지합니다. SMB/RDP 브루트포스 및 비인가 허니팟 접근을 감시합니다."
    description_key = "engines.ransomware_lateral.description"
    config_schema = {
        "brute_force_threshold": {
            "type": int, "default": 20, "min": 5, "max": 100,
            "label": "브루트포스 임계값",
            "label_key": "engines.ransomware_lateral.brute_force_threshold.label",
            "description": "단일 호스트에 대해 윈도우 내 시도된 연결 수가 이 값을 초과하면 브루트포스로 간주.",
            "description_key": "engines.ransomware_lateral.brute_force_threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 300,
            "label": "탐지 윈도우(초)",
            "label_key": "engines.ransomware_lateral.window_seconds.label",
            "description": "확산 활동을 집계하는 시간 윈도우.",
            "description_key": "engines.ransomware_lateral.window_seconds.description",
        },
        "honeypot_ips": {
            "type": list, "default": [],
            "label": "허니팟 IP 목록",
            "label_key": "engines.ransomware_lateral.honeypot_ips.label",
            "description": "네트워크 내에서 사용되지 않는 IP 주소 목록. 접근 시 즉시 경고 발생.",
            "description_key": "engines.ransomware_lateral.honeypot_ips.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)
        self._threshold = config.get("brute_force_threshold", 20)
        self._window = config.get("window_seconds", 60)
        self._honeypots = set(config.get("honeypot_ips", []))

        # (src_ip, dst_ip, port) -> deque of timestamps
        self._attempts: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷에서 허니팟 접근 및 브루트포스 징후를 분석한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # 1. 허니팟 접근 탐지 (즉시 알림)
        if dst_ip in self._honeypots:
            now = time.time()
            if now - self._alerted.get(f"hp:{src_ip}:{dst_ip}", 0) > 300:
                self._alerted[f"hp:{src_ip}:{dst_ip}"] = now
                return Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Honeypot Access Detected",
                    title_key="engines.ransomware_lateral.alerts.honeypot.title",
                    description=(
                        f"Host {src_ip} attempted to access inactive honeypot IP {dst_ip} "
                        f"on port {dst_port}. Strong indicator of internal scanning or malware."
                    ),
                    description_key="engines.ransomware_lateral.alerts.honeypot.description",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    confidence=1.0,
                    metadata={"port": dst_port, "target": "honeypot"},
                )

        # 2. SMB(445) / RDP(3389) 브루트포스 추적
        if flags == "S" and dst_port in (445, 3389):
            self._attempts[(src_ip, dst_ip, dst_port)].append(time.time())

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 연결 시도 횟수를 검사하여 브루트포스 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        for (src_ip, dst_ip, port), times in list(self._attempts.items()):
            while times and times[0] < cutoff:
                times.popleft()
            
            if len(times) >= self._threshold:
                if now - self._alerted.get(f"bf:{src_ip}:{dst_ip}:{port}", 0) > self._window:
                    self._alerted[f"bf:{src_ip}:{dst_ip}:{port}"] = now
                    svc = "SMB" if port == 445 else "RDP"
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title=f"{svc} Brute Force Detected",
                        title_key=f"engines.ransomware_lateral.alerts.brute_force.title",
                        description=(
                            f"Host {src_ip} attempted {len(times)} {svc} connections "
                            f"to {dst_ip} in {self._window}s. Possible credential attack."
                        ),
                        description_key=f"engines.ransomware_lateral.alerts.brute_force.description",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.9,
                        metadata={"service": svc, "port": port, "count": len(times)},
                    ))

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._attempts.clear()
        self._alerted.clear()
