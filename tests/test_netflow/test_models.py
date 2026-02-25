"""FlowRecord 모델 단위 테스트."""

import pytest
from netwatcher.netflow.models import FlowRecord, Protocol


class TestFlowRecord:
    def test_basic_construction(self):
        flow = FlowRecord(
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=443,
            protocol=Protocol.TCP,
            bytes_count=1500,
            packets_count=10,
            start_uptime_ms=1000,
            end_uptime_ms=2000,
            tcp_flags=0x02,
            tos=0,
            src_as=0,
            dst_as=0,
            input_iface=0,
            output_iface=0,
        )
        assert flow.src_ip == "192.168.1.10"
        assert flow.dst_ip == "8.8.8.8"
        assert flow.dst_port == 443
        assert flow.protocol == Protocol.TCP

    def test_duration_ms(self):
        flow = FlowRecord(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol=Protocol.TCP,
            bytes_count=500,
            packets_count=5,
            start_uptime_ms=1000,
            end_uptime_ms=3000,
            tcp_flags=0,
            tos=0, src_as=0, dst_as=0,
            input_iface=0, output_iface=0,
        )
        assert flow.duration_ms == 2000

    def test_duration_ms_zero_when_same(self):
        flow = FlowRecord(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1234, dst_port=80,
            protocol=Protocol.UDP,
            bytes_count=100, packets_count=1,
            start_uptime_ms=5000, end_uptime_ms=5000,
            tcp_flags=0, tos=0, src_as=0, dst_as=0,
            input_iface=0, output_iface=0,
        )
        assert flow.duration_ms == 0

    def test_is_tcp(self):
        flow = FlowRecord(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=0, dst_port=0,
            protocol=Protocol.TCP,
            bytes_count=0, packets_count=0,
            start_uptime_ms=0, end_uptime_ms=0,
            tcp_flags=0x12,  # SYN+ACK
            tos=0, src_as=0, dst_as=0,
            input_iface=0, output_iface=0,
        )
        assert flow.is_tcp is True
        assert flow.is_udp is False

    def test_unknown_protocol(self):
        flow = FlowRecord(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=0, dst_port=0,
            protocol=Protocol.OTHER,
            bytes_count=0, packets_count=0,
            start_uptime_ms=0, end_uptime_ms=0,
            tcp_flags=0, tos=0, src_as=0, dst_as=0,
            input_iface=0, output_iface=0,
        )
        assert flow.is_tcp is False
        assert flow.is_udp is False
