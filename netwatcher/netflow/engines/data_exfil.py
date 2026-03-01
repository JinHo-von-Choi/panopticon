"""NetFlow 기반 데이터 유출 탐지."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from netwatcher.detection.models import Alert, Severity
from netwatcher.netflow.base import NetFlowEngine
from netwatcher.netflow.models import NetFlowV5Record
from netwatcher.utils.network import is_private_ip

class FlowDataExfilEngine(NetFlowEngine):
    """NetFlow 데이터를 기반으로 대량의 외부 전송을 탐지한다."""

    name = "flow_data_exfil"
    description = "NetFlow 데이터를 기반으로 데이터 유출을 탐지합니다. 외부 IP로의 대량 전송 활동을 식별합니다."
    description_key = "engines.flow_data_exfil.description"
    config_schema = {
        "outbound_threshold_mb": {
            "type": int, "default": 100, "min": 10, "max": 2000,
            "label": "외부 전송 임계값(MB)",
            "label_key": "engines.flow_data_exfil.outbound_threshold_mb.label",
            "description": "윈도우 내 외부 IP로 전송된 데이터가 이 값을 초과하면 유출 의심.",
            "description_key": "engines.flow_data_exfil.outbound_threshold_mb.description",
        },
        "window_seconds": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "집계 윈도우(초)",
            "label_key": "engines.flow_data_exfil.window_seconds.label",
            "description": "전송량을 합산하는 시간 단위.",
            "description_key": "engines.flow_data_exfil.window_seconds.description",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._threshold_bytes = config.get("outbound_threshold_mb", 100) * 1024 * 1024
        self._window = config.get("window_seconds", 300)
        # (src_ip, dst_ip) -> total_bytes
        self._outbound_bytes: dict[tuple[str, str], int] = defaultdict(int)
        self._last_reset = time.time()
        self._alerted: dict[tuple[str, str], float] = {}

    def analyze_flow(self, flow: NetFlowV5Record) -> Alert | None:
        """NetFlow 레코드에서 외부 전송량을 합산한다."""
        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        size = flow.bytes
        
        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            self._outbound_bytes[(src_ip, dst_ip)] += size
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        alerts = []
        now = time.time()

        for (src_ip, dst_ip), total in self._outbound_bytes.items():
            if total >= self._threshold_bytes:
                last_alert = self._alerted.get((src_ip, dst_ip), 0)
                if now - last_alert > self._window:
                    self._alerted[(src_ip, dst_ip)] = now
                    mb = total / (1024 * 1024)
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="Massive Data Exfiltration (NetFlow)",
                        title_key="engines.flow_data_exfil.alerts.massive_transfer.title",
                        description=(
                            f"Host {src_ip} sent {mb:.1f} MB to {dst_ip} via NetFlow."
                        ),
                        description_key="engines.flow_data_exfil.alerts.massive_transfer.description",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        confidence=0.8,
                        metadata={"megabytes": round(mb, 1), "window_seconds": self._window},
                    ))

        if now - self._last_reset >= self._window:
            self._outbound_bytes.clear()
            self._last_reset = now
        return alerts
