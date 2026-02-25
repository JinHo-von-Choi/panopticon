"""FlowProcessor 단위 테스트."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from netwatcher.detection.models import Alert, Severity
from netwatcher.netflow.base import FlowEngine
from netwatcher.netflow.models import FlowRecord, Protocol
from netwatcher.netflow.processor import FlowProcessor


def _make_flow(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    dst_port: int = 80,
    protocol: Protocol = Protocol.TCP,
    bytes_count: int = 500,
    packets_count: int = 5,
) -> FlowRecord:
    return FlowRecord(
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=54321, dst_port=dst_port,
        protocol=protocol,
        bytes_count=bytes_count, packets_count=packets_count,
        start_uptime_ms=0, end_uptime_ms=1000,
        tcp_flags=0x02, tos=0, src_as=0, dst_as=0,
        input_iface=0, output_iface=0,
    )


class _AlertingEngine(FlowEngine):
    """테스트용: 모든 플로우에 알림을 발생시키는 엔진."""
    name = "test_alerting"

    def analyze_flow(self, flow: FlowRecord) -> Alert | None:
        return Alert(
            engine="test_alerting",
            severity=Severity.WARNING,
            title="Test Alert",
            source_ip=flow.src_ip,
            dest_ip=flow.dst_ip,
        )


class _SilentEngine(FlowEngine):
    """테스트용: 아무 알림도 발생시키지 않는 엔진."""
    name = "test_silent"

    def analyze_flow(self, flow: FlowRecord) -> Alert | None:
        return None


class TestFlowProcessor:
    def setup_method(self):
        self.dispatcher = MagicMock()
        self.dispatcher.enqueue = MagicMock()

    def test_no_engines_no_alerts(self):
        proc = FlowProcessor(dispatcher=self.dispatcher)
        proc.on_flows([_make_flow()])
        self.dispatcher.enqueue.assert_not_called()

    def test_alerting_engine_dispatches(self):
        proc = FlowProcessor(dispatcher=self.dispatcher)
        proc.register_engine(_AlertingEngine({"enabled": True}))
        proc.on_flows([_make_flow(src_ip="192.168.1.1")])
        self.dispatcher.enqueue.assert_called_once()
        alert = self.dispatcher.enqueue.call_args[0][0]
        assert alert.source_ip == "192.168.1.1"

    def test_silent_engine_no_dispatch(self):
        proc = FlowProcessor(dispatcher=self.dispatcher)
        proc.register_engine(_SilentEngine({"enabled": True}))
        proc.on_flows([_make_flow()])
        self.dispatcher.enqueue.assert_not_called()

    def test_multiple_flows_multiple_alerts(self):
        proc = FlowProcessor(dispatcher=self.dispatcher)
        proc.register_engine(_AlertingEngine({"enabled": True}))
        proc.on_flows([_make_flow(), _make_flow(), _make_flow()])
        assert self.dispatcher.enqueue.call_count == 3

    def test_disabled_engine_skipped(self):
        proc = FlowProcessor(dispatcher=self.dispatcher)
        engine = _AlertingEngine({"enabled": False})
        proc.register_engine(engine)
        proc.on_flows([_make_flow()])
        self.dispatcher.enqueue.assert_not_called()

    def test_engine_exception_does_not_propagate(self):
        """엔진이 예외를 발생시켜도 FlowProcessor가 계속 동작해야 한다."""
        class _BrokenEngine(FlowEngine):
            name = "broken"
            def analyze_flow(self, flow: FlowRecord) -> Alert | None:
                raise RuntimeError("broken engine")

        proc = FlowProcessor(dispatcher=self.dispatcher)
        proc.register_engine(_BrokenEngine({"enabled": True}))
        # 예외 없이 완료되어야 함
        proc.on_flows([_make_flow()])
        self.dispatcher.enqueue.assert_not_called()

    def test_flow_count_tracked(self):
        proc = FlowProcessor(dispatcher=self.dispatcher)
        proc.on_flows([_make_flow(), _make_flow()])
        assert proc.total_flows == 2
