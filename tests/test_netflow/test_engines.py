"""FlowEngine 구현체 단위 테스트."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatcher.detection.models import Severity
from netwatcher.netflow.models import FlowRecord, Protocol
from netwatcher.netflow.engines.port_scan import FlowPortScanEngine
from netwatcher.netflow.engines.data_exfil import FlowDataExfilEngine


def _big_flow(src: str, dst: str, bytes_count: int) -> FlowRecord:
    return FlowRecord(
        src_ip=src, dst_ip=dst,
        src_port=54321, dst_port=443,
        protocol=Protocol.TCP,
        bytes_count=bytes_count, packets_count=100,
        start_uptime_ms=0, end_uptime_ms=5000,
        tcp_flags=0x02, tos=0, src_as=0, dst_as=0,
        input_iface=0, output_iface=0,
    )


def _tcp_flow(
    src: str, dst: str, dst_port: int, bytes_count: int = 100
) -> FlowRecord:
    return FlowRecord(
        src_ip=src, dst_ip=dst,
        src_port=54321, dst_port=dst_port,
        protocol=Protocol.TCP,
        bytes_count=bytes_count, packets_count=1,
        start_uptime_ms=0, end_uptime_ms=100,
        tcp_flags=0x02, tos=0, src_as=0, dst_as=0,
        input_iface=0, output_iface=0,
    )


class TestFlowPortScanEngine:
    def setup_method(self):
        self.engine = FlowPortScanEngine({
            "enabled": True,
            "window_seconds": 60,
            "threshold": 10,
            "cooldown_seconds": 300,
        })

    def test_single_flow_no_alert(self):
        flow = _tcp_flow("10.0.0.1", "10.0.0.2", 80)
        alert = self.engine.analyze_flow(flow)
        assert alert is None
        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_port_scan_detected(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        for port in range(1, 20):  # 19 unique ports → threshold=10 초과
            self.engine.analyze_flow(_tcp_flow(src, dst, port))

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity == Severity.WARNING
        assert alert.source_ip == src
        assert alert.dest_ip == dst
        assert "Flow Port Scan" in alert.title

    def test_same_port_no_scan(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        for _ in range(50):  # 같은 포트 50번 → 스캔 아님
            self.engine.analyze_flow(_tcp_flow(src, dst, 80))

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_different_destinations_independent(self):
        # 같은 src에서 다른 dst로 각각 5개 포트 → 각각 threshold=10 미달
        src = "10.0.0.1"
        for port in range(1, 6):
            self.engine.analyze_flow(_tcp_flow(src, "10.0.0.2", port))
            self.engine.analyze_flow(_tcp_flow(src, "10.0.0.3", port))

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_cooldown_suppresses_repeat(self):
        src, dst = "10.0.0.1", "10.0.0.2"
        for port in range(1, 20):
            self.engine.analyze_flow(_tcp_flow(src, dst, port))

        alerts1 = self.engine.on_tick(time.time())
        assert len(alerts1) == 1

        # 즉시 재틱 → cooldown 내이므로 알림 없어야 함
        for port in range(20, 40):
            self.engine.analyze_flow(_tcp_flow(src, dst, port))
        alerts2 = self.engine.on_tick(time.time())
        assert len(alerts2) == 0


class TestFlowDataExfilEngine:
    MB = 1024 * 1024

    def setup_method(self):
        self.engine = FlowDataExfilEngine({
            "enabled": True,
            "byte_threshold": 50 * self.MB,  # 50MB
            "window_seconds": 3600,
        })

    def test_small_transfer_no_alert(self):
        flow = _big_flow("192.168.1.10", "8.8.8.8", 1 * self.MB)
        assert self.engine.analyze_flow(flow) is None

    def test_large_external_transfer_detected(self):
        src, dst = "192.168.1.10", "1.2.3.4"  # 외부 IP
        # 50MB threshold 초과: 51MB 전송
        alert = self.engine.analyze_flow(_big_flow(src, dst, 51 * self.MB))
        assert alert is not None
        assert alert.source_ip == src
        assert alert.dest_ip == dst
        assert alert.severity == Severity.WARNING

    def test_internal_to_internal_no_alert(self):
        # 내부 → 내부: 탐지 안 함
        flow = _big_flow("192.168.1.10", "192.168.1.20", 100 * self.MB)
        assert self.engine.analyze_flow(flow) is None

    def test_cumulative_threshold(self):
        # 여러 플로우가 누적되어 임계값 초과
        src, dst = "10.0.0.5", "203.0.113.1"
        result = None
        for _ in range(10):
            result = self.engine.analyze_flow(_big_flow(src, dst, 6 * self.MB))
        # 10 * 6MB = 60MB > 50MB
        assert result is not None

    def test_different_destinations_independent(self):
        # 다른 목적지는 독립 집계
        src = "192.168.1.10"
        alert1 = self.engine.analyze_flow(_big_flow(src, "1.1.1.1", 30 * self.MB))
        alert2 = self.engine.analyze_flow(_big_flow(src, "2.2.2.2", 30 * self.MB))
        # 각각 30MB < 50MB → 모두 None
        assert alert1 is None
        assert alert2 is None
