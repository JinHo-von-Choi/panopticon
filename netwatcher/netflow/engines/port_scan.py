"""플로우 기반 포트 스캔 탐지 엔진."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from netwatcher.detection.models import Alert, Severity
from netwatcher.netflow.base import FlowEngine
from netwatcher.netflow.models import FlowRecord

logger = logging.getLogger("netwatcher.netflow.engines.port_scan")


class FlowPortScanEngine(FlowEngine):
    """NetFlow 플로우에서 포트 스캔을 탐지한다.

    (src_ip, dst_ip) 쌍별로 시간 윈도우 내에 관찰된 고유 목적지 포트 수를 추적한다.
    임계값 초과 시 알림 발생.
    """

    name        = "flow_port_scan"
    description = "NetFlow 기반 포트 스캔 탐지 — SPAN 없는 환경에서도 동작."

    config_schema: dict[str, Any] = {
        "window_seconds":   {"type": int, "default": 60,  "min": 10,  "max": 3600},
        "threshold":        {"type": int, "default": 15,  "min": 5,   "max": 1000},
        "cooldown_seconds": {"type": int, "default": 300, "min": 30,  "max": 86400},
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._window    = config.get("window_seconds",   60)
        self._threshold = config.get("threshold",        15)
        self._cooldown  = config.get("cooldown_seconds", 300)

        # (src_ip, dst_ip) → {dst_port: first_seen_ts}
        self._port_table: dict[tuple[str, str], dict[int, float]] = defaultdict(dict)
        self._alerted_at: dict[tuple[str, str], float]            = {}

    def analyze_flow(self, flow: FlowRecord) -> Alert | None:
        """플로우를 받아 포트-접근 테이블을 업데이트한다.

        스캔 판정은 on_tick에서 일괄 처리하므로 analyze_flow는 None만 반환한다.
        """
        now = time.time()
        key = (flow.src_ip, flow.dst_ip)
        self._port_table[key][flow.dst_port] = now
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """만료 항목 제거 후 임계값 초과 쌍을 탐지한다."""
        now    = timestamp
        cutoff = now - self._window
        alerts: list[Alert] = []

        for key in list(self._port_table.keys()):
            port_times = self._port_table[key]

            # 윈도우 밖 항목 제거
            self._port_table[key] = {
                p: t for p, t in port_times.items() if t >= cutoff
            }
            if not self._port_table[key]:
                del self._port_table[key]
                continue

            unique_ports = len(self._port_table[key])
            if unique_ports < self._threshold:
                continue

            # cooldown 확인
            last_alerted = self._alerted_at.get(key, 0.0)
            if now - last_alerted < self._cooldown:
                continue

            src_ip, dst_ip = key
            self._alerted_at[key] = now
            alerts.append(Alert(
                engine      = self.name,
                severity    = Severity.WARNING,
                title       = "Flow Port Scan Detected",
                description = (
                    f"{src_ip} → {dst_ip}: {unique_ports}개 고유 포트 접근 "
                    f"({self._window}초 내, 임계값 {self._threshold})"
                ),
                source_ip   = src_ip,
                dest_ip     = dst_ip,
                confidence  = 0.75,
                metadata    = {
                    "unique_ports":    unique_ports,
                    "window_seconds":  self._window,
                    "source":          "netflow_v5",
                },
            ))

        return alerts

    def shutdown(self) -> None:
        self._port_table.clear()
        self._alerted_at.clear()
