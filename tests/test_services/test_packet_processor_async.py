"""비동기 엔진 분배의 처리 순서와 큐 포화 시 손실 기록을 검증한다."""

import asyncio
from unittest.mock import MagicMock

import pytest

from netwatcher.services.packet_processor import PacketProcessor


class _Registry:
    def __init__(self):
        self.running = 0
        self.peak = 0
        self.seen = []

    async def process_packet_async(self, packet):
        self.running += 1
        self.peak = max(self.peak, self.running)
        await asyncio.sleep(0)
        self.seen.append(packet)
        self.running -= 1
        return []


def _processor(registry, size=10):
    return PacketProcessor(registry=MagicMock(), dispatcher=None, pcap_writer=MagicMock(), dns_resolver=MagicMock(),
                           async_registry=registry, async_queue_size=size)


@pytest.mark.asyncio
async def test_packets_are_processed_one_at_a_time_in_order():
    registry = _Registry()
    processor = _processor(registry)
    for packet in ("a", "b", "c"):
        processor._run_engines_local(packet)
    while len(registry.seen) < 3:
        await asyncio.sleep(0)
    await processor.stop_async_dispatch()
    assert registry.seen == ["a", "b", "c"] and registry.peak == 1


@pytest.mark.asyncio
async def test_full_queue_counts_the_lost_packet():
    processor = _processor(_Registry(), size=1)
    processor._run_engines_local("a")
    processor._run_engines_local("b")
    assert processor.async_dropped == 1
    await processor.stop_async_dispatch()
