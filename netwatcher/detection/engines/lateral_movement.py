"""측면 이동(Lateral Movement) 탐지: 민감 포트 접근, 피벗 체인 분석."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, Packet, TCP

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.network import is_private_ip

logger = logging.getLogger("netwatcher.detection.engines.lateral_movement")

# 내부망 측면 이동에 자주 사용되는 민감 서비스 포트
_SENSITIVE_PORTS = {
    22: "SSH",
    445: "SMB/AD",
    3389: "RDP",
    5900: "VNC",
    23: "Telnet",
}


class LateralMovementEngine(DetectionEngine):
    """내부 네트워크에서의 공격 확산 시도를 탐지한다.

    - Sensitive Access: 단일 호스트가 짧은 시간 내 다수의 내부 서버 민감 포트에 접근
    - Pivot Chain: 특정 호스트를 거쳐 다른 호스트로 연속적인 접근 시도 (추적 예정)
    """

    name = "lateral_movement"
    description = "측면 이동(Lateral Movement) 활동을 탐지합니다. 내부망 내 민감 포트 접근 및 공격 확산 징후를 식별합니다."
    description_key = "engines.lateral_movement.description"
    config_schema = {
        "access_threshold": {
            "type": int, "default": 3, "min": 2, "max": 20,
            "label": "민감 접근 임계값",
            "label_key": "engines.lateral_movement.access_threshold.label",
            "description": "윈도우 내 접근한 고유 내부 서버 수가 이 값을 초과하면 측면 이동 의심.",
            "description_key": "engines.lateral_movement.access_threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "탐지 윈도우(초)",
            "label_key": "engines.lateral_movement.window_seconds.label",
            "description": "내부 접근 활동을 집계하는 시간 윈도우.",
            "description_key": "engines.lateral_movement.window_seconds.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화하고 접근 추적 버퍼를 생성한다."""
        super().__init__(config)
        self._threshold = config.get("access_threshold", 3)
        self._window = config.get("window_seconds", 300)

        # src_ip -> deque of (timestamp, dst_ip, port)
        self._access_log: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """내부망 간의 TCP 연결 시도를 분석하여 민감 포트 접근을 추적한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # 내부 -> 내부 통신 중 SYN 패킷만 추적
        if flags == "S" and is_private_ip(src_ip) and is_private_ip(dst_ip):
            if dst_port in _SENSITIVE_PORTS:
                self._access_log[src_ip].append((time.time(), dst_ip, dst_port))

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 내부 접근 패턴을 검사하여 측면 이동 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        for src_ip, logs in list(self._access_log.items()):
            while logs and logs[0][0] < cutoff:
                logs.popleft()
            if not logs:
                continue

            unique_targets = set(d for _, d, _ in logs)
            if len(unique_targets) >= self._threshold:
                if now - self._alerted.get(src_ip, 0) > self._window:
                    self._alerted[src_ip] = now
                    ports = sorted(set(p for _, _, p in logs))
                    port_names = [f"{p}({_SENSITIVE_PORTS.get(p, 'unknown')})" for p in ports]
                    
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="Internal Lateral Movement Detected",
                        title_key="engines.lateral_movement.alerts.lateral_move.title",
                        description=(
                            f"Host {src_ip} accessed {len(unique_targets)} internal servers "
                            f"via sensitive ports ({', '.join(port_names)}) in {self._window}s. "
                            "Likely lateral movement or credential spraying."
                        ),
                        description_key="engines.lateral_movement.alerts.lateral_move.description",
                        source_ip=src_ip,
                        confidence=0.8,
                        metadata={
                            "target_count": len(unique_targets),
                            "targets": list(unique_targets),
                            "ports": ports,
                            "window_seconds": self._window,
                        },
                    ))

        return alerts

    def shutdown(self) -> None:
        """엔진 상태를 초기화한다."""
        self._access_log.clear()
        self._alerted.clear()
