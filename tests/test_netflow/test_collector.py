"""UDP 수신 중단은 소켓의 비동기 정리보다 먼저 효력이 생긴다."""

import asyncio
import socket

import pytest

from netwatcher.netflow.collector import FlowCollector
from netwatcher.netflow.processor import FlowProcessor
from tests.test_netflow.test_parser import _make_v5_packet


@pytest.mark.asyncio
async def test_collector_discards_real_udp_and_queued_callback_after_intake_stop(monkeypatch):
    processor = FlowProcessor()
    collector = FlowCollector(processor, "127.0.0.1", 0)
    await collector.start()
    payload = _make_v5_packet([{"src_ip": "192.0.2.83", "dst_ip": "203.0.113.9", "dst_port": 443}])
    received = asyncio.Event()
    protocol = collector._protocol
    original = protocol.datagram_received
    def observe(data, address):
        original(data, address)
        received.set()
    monkeypatch.setattr(protocol, "datagram_received", observe)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            address = collector._transport.get_extra_info("sockname")
            sender.sendto(payload, address)
            await asyncio.wait_for(received.wait(), 2)
            assert processor.total_flows == 1
            received.clear()
            collector.stop_accepting()
            assert collector._transport is not None
            sender.sendto(payload, address)
            await asyncio.wait_for(received.wait(), 2)
            assert processor.total_flows == 1
            original(payload, address)
            assert processor.total_flows == 1
    finally:
        collector.stop()
    assert collector._transport is None


@pytest.mark.asyncio
async def test_closed_collector_protocol_stays_stopped_after_explicit_restart():
    processor = FlowProcessor()
    collector = FlowCollector(processor, "127.0.0.1", 0)
    await collector.start()
    old_protocol = collector._protocol
    payload = _make_v5_packet([{"src_ip": "192.0.2.83", "dst_ip": "203.0.113.9", "dst_port": 443}])
    collector.stop()
    await collector.start()
    try:
        old_protocol.datagram_received(payload, ("127.0.0.1", 12345))
        assert processor.total_flows == 0
        collector._protocol.datagram_received(payload, ("127.0.0.1", 12345))
        assert processor.total_flows == 1
    finally:
        collector.stop()
