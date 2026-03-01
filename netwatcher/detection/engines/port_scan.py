"""포트 스캔 탐지: TCP SYN/FIN/NULL/XMAS 스캔."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.utils.network import is_private_ip

logger = logging.getLogger("netwatcher.detection.engines.port_scan")


class PortScanEngine(DetectionEngine):
    """짧은 시간 동안 다수의 고유 포트에 접속을 시도하는 활동을 탐지한다.

    - SYN 스캔: 일반적인 연결 시도
    - Stealth 스캔: FIN, NULL, XMAS (비정상 플래그 조합)
    """

    name = "port_scan"
    description = "포트 스캔 활동을 탐지합니다. 짧은 시간 내에 다수의 포트를 조사하는 스캐너 및 공격자를 식별합니다."
    description_key = "engines.port_scan.description"
    config_schema = {
        "threshold": {
            "type": int, "default": 15, "min": 5, "max": 100,
            "label": "포트 스캔 임계값",
            "label_key": "engines.port_scan.threshold.label",
            "description": "윈도우 내 고유 목적지 포트 수가 이 값을 초과하면 포트 스캔으로 판단.",
            "description_key": "engines.port_scan.threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "탐지 윈도우(초)",
            "label_key": "engines.port_scan.window_seconds.label",
            "description": "포트 스캔 활동을 집계하는 슬라이딩 윈도우 길이.",
            "description_key": "engines.port_scan.window_seconds.description",
        },
        "stealth_threshold": {
            "type": int, "default": 3, "min": 1, "max": 20,
            "label": "Stealth 스캔 임계값",
            "label_key": "engines.port_scan.stealth_threshold.label",
            "description": "비정상 TCP 플래그(NULL, XMAS 등)를 가진 패킷이 이 횟수를 초과하면 즉시 경고.",
            "description_key": "engines.port_scan.stealth_threshold.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화하고 포트 추적 버퍼를 생성한다."""
        super().__init__(config)
        self._threshold = config.get("threshold", 15)
        self._window = config.get("window_seconds", 60)
        self._stealth_threshold = config.get("stealth_threshold", 3)

        # source_ip -> deque of (timestamp, dst_port)
        self._scans: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        # source_ip -> stealth_packet_count
        self._stealth_counts: dict[str, int] = defaultdict(int)
        self._alerted: dict[str, float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """TCP 패킷에서 비정상 플래그 또는 대량의 포트 접속 시도를 탐지한다."""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        now = time.time()

        # Stealth 스캔 탐지 (NULL, XMAS 등)
        # NULL: 0, XMAS: FIN+PSH+URG (0x29)
        is_stealth = False
        if flags == 0:  # NULL Scan
            is_stealth = True
        elif int(flags) == 0x29:  # XMAS Scan
            is_stealth = True
        elif flags == "F":  # FIN Scan (연결 없이 FIN만 전송)
            is_stealth = True

        if is_stealth:
            self._stealth_counts[src_ip] += 1
            if self._stealth_counts[src_ip] >= self._stealth_threshold:
                if now - self._alerted.get(f"{src_ip}:stealth", 0) > self._window:
                    self._alerted[f"{src_ip}:stealth"] = now
                    return Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="Stealth Port Scan Detected",
                        title_key="engines.port_scan.alerts.stealth.title",
                        description=(
                            f"Abnormal TCP flags ({flags}) from {src_ip}. "
                            "Indicates a stealth port scan attempt (NULL/XMAS/FIN)."
                        ),
                        description_key="engines.port_scan.alerts.stealth.description",
                        source_ip=src_ip,
                        confidence=0.9,
                        metadata={"flags": str(flags), "count": self._stealth_counts[src_ip]},
                    )

        # 일반 포트 스캔 추적
        self._scans[src_ip].append((now, dst_port))
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """주기적으로 윈도우 내 고유 포트 수를 확인하여 포트 스캔 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        for src_ip, attempts in list(self._scans.items()):
            # 윈도우 밖 항목 제거
            while attempts and attempts[0][0] < cutoff:
                attempts.popleft()

            if not attempts:
                continue

            unique_ports = set(p for _, p in attempts)
            
            # 내부망 간 통신 여부 확인
            is_internal = is_private_ip(src_ip)
            effective_threshold = self._threshold * 3 if is_internal else self._threshold

            if len(unique_ports) >= effective_threshold:
                if now - self._alerted.get(src_ip, 0) > self._window:
                    self._alerted[src_ip] = now
                    confidence = min(1.0, 0.6 + (len(unique_ports) / 100))
                    title = "Port Scan Detected" + (" (Internal)" if is_internal else "")
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title=title,
                        title_key="engines.port_scan.alerts.scan.title",
                        description=(
                            f"{src_ip} scanned {len(unique_ports)} unique ports "
                            f"in {self._window}s. Possible reconnaissance."
                        ),
                        description_key="engines.port_scan.alerts.scan.description",
                        source_ip=src_ip,
                        confidence=confidence,
                        metadata={
                            "unique_ports": len(unique_ports),
                            "count": len(unique_ports),
                            "window_seconds": self._window,
                            "sample_ports": list(unique_ports)[:10],
                            "is_internal": is_internal,
                        },
                    ))

        return alerts

    def shutdown(self) -> None:
        """엔진 데이터를 초기화한다."""
        self._scans.clear()
        self._stealth_counts.clear()
        self._alerted.clear()
