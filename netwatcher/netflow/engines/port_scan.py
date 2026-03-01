"""NetFlow 기반 포트 스캔 탐지."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

from netwatcher.detection.models import Alert, Severity
from netwatcher.netflow.base import NetFlowEngine
from netwatcher.netflow.models import NetFlowV5Record

class FlowPortScanEngine(NetFlowEngine):
    """NetFlow 레코드를 분석하여 포트 스캔을 탐지한다 (SPAN 없는 환경용)."""

    name = "flow_port_scan"
    description = "NetFlow 데이터를 기반으로 포트 스캔을 탐지합니다. SPAN 포트 구성이 불가능한 환경에서 대안으로 사용됩니다."
    description_key = "engines.flow_port_scan.description"
    config_schema = {
        "threshold": {
            "type": int, "default": 20, "min": 5, "max": 200,
            "label": "포트 스캔 임계값",
            "label_key": "engines.flow_port_scan.threshold.label",
            "description": "윈도우 내 고유 목적지 포트 수가 이 값을 초과하면 포트 스캔으로 판단.",
            "description_key": "engines.flow_port_scan.threshold.description",
        },
        "window_seconds": {
            "type": int, "default": 60, "min": 10, "max": 600,
            "label": "탐지 윈도우(초)",
            "label_key": "engines.flow_port_scan.window_seconds.label",
            "description": "포트 스캔 활동을 집계하는 시간 윈도우.",
            "description_key": "engines.flow_port_scan.window_seconds.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._threshold = config.get("threshold", 20)
        self._window = config.get("window_seconds", 60)
        # src_ip -> deque of (timestamp, dst_port)
        self._scans: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._alerted: dict[str, float] = {}

    def analyze_flow(self, flow: NetFlowV5Record) -> Alert | None:
        """NetFlow 레코드에서 목적지 포트를 추적한다."""
        src_ip = flow.src_ip
        dst_port = flow.dst_port
        now = time.time()
        self._scans[src_ip].append((now, dst_port))
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        alerts = []
        now = time.time()
        cutoff = now - self._window

        for src_ip, attempts in list(self._scans.items()):
            while attempts and attempts[0][0] < cutoff:
                attempts.popleft()
            if not attempts:
                continue

            unique_ports = set(p for _, p in attempts)
            if len(unique_ports) >= self._threshold:
                if now - self._alerted.get(src_ip, 0) > self._window:
                    self._alerted[src_ip] = now
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.WARNING,
                        title="Port Scan Detected (NetFlow)",
                        title_key="engines.flow_port_scan.alerts.scan.title",
                        description=(
                            f"Host {src_ip} scanned {len(unique_ports)} ports "
                            f"via NetFlow in {self._window}s."
                        ),
                        description_key="engines.flow_port_scan.alerts.scan.description",
                        source_ip=src_ip,
                        confidence=0.7,
                        metadata={"unique_ports": len(unique_ports), "window_seconds": self._window},
                    ))
        return alerts
