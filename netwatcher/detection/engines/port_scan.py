"""포트 스캔 탐지 엔진 (SYN, FIN, NULL, XMAS, ACK 스캔 탐지)."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs

logger = logging.getLogger("netwatcher.detection.engines.port_scan")

# TCP 플래그 상수
_FIN = 0x01
_SYN = 0x02
_RST = 0x04
_PSH = 0x08
_ACK = 0x10
_URG = 0x20


def _classify_scan(flags: int) -> str | None:
    """TCP 패킷을 스캔 유형으로 분류한다. 스캔 패턴이 아니면 None을 반환한다."""
    if (flags & _SYN) and not (flags & _ACK):
        return "SYN"
    if flags == 0:
        return "NULL"
    if (flags & (_FIN | _PSH | _URG)) == (_FIN | _PSH | _URG):
        return "XMAS"
    if (flags & _FIN) and not (flags & (_SYN | _ACK | _RST)):
        return "FIN"
    if (flags & _ACK) and not (flags & (_SYN | _FIN | _RST | _PSH)):
        return "ACK"
    return None


class PortScanEngine(DetectionEngine):
    """포트 스캔 활동을 탐지한다 (SYN, FIN, NULL, XMAS, ACK 스캔).

    시간 윈도우 내 (src_ip -> dst_ip) 쌍별 고유 목적지 포트를 추적한다.
    임계값 초과 시 알림을 트리거한다.
    """

    name = "port_scan"
    description = "네트워크 포트 스캔 활동을 탐지합니다. SYN/FIN/NULL/Xmas 스캔 등 다양한 스캔 기법을 식별합니다."
    config_schema = {
        "window_seconds": {
            "type": int, "default": 60, "min": 5, "max": 600,
            "label": "탐지 윈도우(초)",
            "description": "포트 스캔 활동을 집계하는 시간 윈도우. "
                           "짧으면 빠른 스캔만 탐지, 길면 느린 스텔스 스캔도 탐지.",
        },
        "threshold": {
            "type": int, "default": 15, "min": 3, "max": 1000,
            "label": "포트 수 임계값",
            "description": "윈도우 내 (출발지->목적지) 쌍에서 스캔된 고유 포트 수가 이 값을 초과하면 알림 발생. "
                           "낮추면 민감도 증가(소규모 스캔도 탐지), 높이면 대규모 스캔만 탐지.",
        },
        "alerted_cooldown_seconds": {
            "type": int, "default": 300, "min": 10, "max": 3600,
            "label": "재알림 쿨다운(초)",
            "description": "동일 (출발지->목적지) 쌍에 대해 알림 재발송까지 대기 시간.",
        },
        "max_tracked_connections": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 연결 수",
            "description": "메모리에 유지하는 (출발지, 목적지) 쌍의 최대 수. "
                           "대규모 네트워크에서는 증가 필요.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """포트 스캔 엔진을 초기화한다. 윈도우, 임계값, 쿨다운 등을 설정한다."""
        super().__init__(config)
        self._window = config.get("window_seconds", 60)
        self._threshold = config.get("threshold", 15)
        self._alerted_cooldown = config.get("alerted_cooldown_seconds", 300)
        self._max_connections = config.get("max_tracked_connections", 10000)

        # (src_ip, dst_ip) -> (timestamp, port, scan_type) 리스트
        self._connections: dict[tuple[str, str], list[tuple[float, int, str]]] = defaultdict(list)
        # (src_ip, dst_ip) -> 마지막 알림 타임스탬프 (쿨다운 기반)
        self._alerted: dict[tuple[str, str], float] = {}

    def analyze(self, packet: Packet) -> Alert | None:
        """TCP 패킷에서 스캔 유형을 분류하고 연결 정보를 기록한다."""
        if not packet.haslayer(TCP):
            return None

        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip or not dst_ip:
            return None

        tcp = packet[TCP]
        scan_type = _classify_scan(int(tcp.flags))
        if scan_type is None:
            return None

        dst_port = tcp.dport
        now = time.time()

        key = (src_ip, dst_ip)

        # 메모리 소진 방지를 위한 최대 추적 연결 수 제한
        if key not in self._connections and len(self._connections) >= self._max_connections:
            # 가장 오래된 항목 제거
            oldest_key = min(
                self._connections,
                key=lambda k: self._connections[k][0][0] if self._connections[k] else float('inf'),
            )
            del self._connections[oldest_key]

        self._connections[key].append((now, dst_port, scan_type))

        return None  # 분석은 on_tick에서 수행

    def on_tick(self, timestamp: float) -> list[Alert]:
        """윈도우 내 고유 포트 수를 검사하여 포트 스캔 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        keys_to_delete = []
        for key, entries in self._connections.items():
            # 오래된 항목 제거
            entries[:] = [(ts, port, st) for ts, port, st in entries if ts > cutoff]

            if not entries:
                keys_to_delete.append(key)
                continue

            unique_ports = set(port for _, port, _ in entries)
            scan_types   = sorted(set(st for _, _, st in entries))
            src_ip, dst_ip = key

            # 영구 집합 대신 쿨다운 검사
            last_alert = self._alerted.get(key, 0)
            if (
                len(unique_ports) >= self._threshold
                and now - last_alert > self._alerted_cooldown
            ):
                self._alerted[key] = now
                port_list = sorted(unique_ports)[:20]
                confidence = min(1.0, len(unique_ports) / (self._threshold * 2))
                scan_label = "/".join(scan_types)
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Port Scan Detected ({scan_label})",
                    description=(
                        f"{src_ip} scanned {len(unique_ports)} ports on {dst_ip} "
                        f"in {self._window}s ({scan_label} scan). Ports: {port_list}"
                    ),
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    metadata={
                        "unique_ports": len(unique_ports),
                        "sample_ports": port_list,
                        "scan_types": scan_types,
                        "window_seconds": self._window,
                        "confidence": round(confidence, 2),
                    },
                ))

        for key in keys_to_delete:
            del self._connections[key]

        # 만료된 쿨다운 제거
        expired = [
            k for k, ts in self._alerted.items()
            if now - ts > self._alerted_cooldown
        ]
        for k in expired:
            del self._alerted[k]

        return alerts

    def shutdown(self) -> None:
        """엔진 종료 시 추적 데이터를 정리한다."""
        self._connections.clear()
        self._alerted.clear()
