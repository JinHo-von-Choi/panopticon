"""플로우 기반 데이터 유출 탐지 엔진."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict
from typing import Any

from netwatcher.detection.models import Alert, Severity
from netwatcher.netflow.base import FlowEngine
from netwatcher.netflow.models import FlowRecord

logger = logging.getLogger("netwatcher.netflow.engines.data_exfil")

_RFC1918 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
]


def _is_internal(ip: str) -> bool:
    """IP 주소가 RFC 1918 사설망 대역인지 확인한다."""
    try:
        addr = ipaddress.IPv4Address(ip)
        return any(addr in net for net in _RFC1918)
    except ValueError:
        return False


class FlowDataExfilEngine(FlowEngine):
    """NetFlow 플로우에서 대용량 외부 전송(데이터 유출)을 탐지한다.

    내부 IP에서 외부 IP로의 전송 바이트를 시간 윈도우별로 누적한다.
    임계값 초과 시 알림 발생.
    """

    name        = "flow_data_exfil"
    description = "NetFlow 기반 대용량 외부 전송 탐지 — SPAN 없는 환경에서도 동작."

    config_schema: dict[str, Any] = {
        "byte_threshold": {"type": int, "default": 104857600, "min": 1048576},  # 100MB
        "window_seconds": {"type": int, "default": 3600,      "min": 60},
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._threshold = config.get("byte_threshold", 104_857_600)  # 100MB
        self._window    = config.get("window_seconds",  3600)

        # (src_ip, dst_ip) → list[(bytes, timestamp)]
        self._transfer_log: dict[tuple[str, str], list[tuple[int, float]]] = (
            defaultdict(list)
        )

    def analyze_flow(self, flow: FlowRecord) -> Alert | None:
        """플로우를 받아 내부→외부 전송이면 누적 집계 후 임계값 초과 시 알림."""
        if not _is_internal(flow.src_ip) or _is_internal(flow.dst_ip):
            return None

        now = time.time()
        key = (flow.src_ip, flow.dst_ip)

        # 현재 플로우 추가
        self._transfer_log[key].append((flow.bytes_count, now))

        # 윈도우 밖 항목 제거
        cutoff = now - self._window
        self._transfer_log[key] = [
            (b, t) for b, t in self._transfer_log[key] if t >= cutoff
        ]

        total_bytes = sum(b for b, _ in self._transfer_log[key])
        if total_bytes < self._threshold:
            return None

        # AlertDispatcher의 자체 rate limiting에 중복 억제를 위임한다.
        mb           = total_bytes / 1024 / 1024
        threshold_mb = self._threshold / 1024 / 1024

        return Alert(
            engine      = self.name,
            severity    = Severity.WARNING,
            title       = "Flow Data Exfiltration Detected",
            description = (
                f"{flow.src_ip} → {flow.dst_ip}: {mb:.1f}MB 외부 전송 "
                f"({self._window}초 내, 임계값 {threshold_mb:.0f}MB)"
            ),
            source_ip   = flow.src_ip,
            dest_ip     = flow.dst_ip,
            confidence  = 0.65,
            metadata    = {
                "total_bytes":     total_bytes,
                "threshold_bytes": self._threshold,
                "window_seconds":  self._window,
                "source":          "netflow_v5",
            },
        )

    def shutdown(self) -> None:
        self._transfer_log.clear()
