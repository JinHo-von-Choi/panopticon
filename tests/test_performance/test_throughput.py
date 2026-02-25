"""Performance/throughput tests (skeleton for baseline measurements)."""

from __future__ import annotations

import time

import pytest

from netwatcher.alerts.rate_limiter import RateLimiter
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.registry import EngineRegistry
from netwatcher.utils.config import Config

from scapy.all import IP, TCP, UDP, Ether


def _make_tcp_packet(src_ip="192.168.1.100", dst_ip="10.0.0.1", sport=12345, dport=80):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / \
           IP(src=src_ip, dst=dst_ip) / \
           TCP(sport=sport, dport=dport, flags="S")


class TestEngineThroughput:
    def test_engine_throughput(self, config):
        """Measure throughput: 10000 packets through EngineRegistry."""
        registry = EngineRegistry(config)
        registry.discover_and_register()

        packets = [
            _make_tcp_packet(dport=80 + (i % 100))
            for i in range(10000)
        ]

        start = time.monotonic()
        total_alerts = 0
        for pkt in packets:
            alerts = registry.process_packet(pkt)
            total_alerts += len(alerts)
        elapsed = time.monotonic() - start

        pps = len(packets) / elapsed if elapsed > 0 else float("inf")
        print(f"\nEngine throughput: {pps:.0f} packets/sec ({elapsed:.3f}s for {len(packets)} packets, {total_alerts} alerts)")

        # Baseline: should process at least 1000 pps
        assert pps > 1000, f"Engine throughput too low: {pps:.0f} pps"

    def test_rate_limiter_throughput(self):
        """Measure rate limiter throughput: 100000 allow() calls."""
        rl = RateLimiter(window_seconds=300, max_count=1000000)

        start = time.monotonic()
        for i in range(100000):
            rl.allow(f"key_{i % 1000}")
        elapsed = time.monotonic() - start

        ops = 100000 / elapsed if elapsed > 0 else float("inf")
        print(f"\nRate limiter throughput: {ops:.0f} ops/sec ({elapsed:.3f}s)")

        # Should handle at least 100k ops/sec
        assert ops > 100000, f"Rate limiter too slow: {ops:.0f} ops/sec"

    def test_rate_limiter_cleanup(self):
        """Cleanup should handle large key sets efficiently."""
        rl = RateLimiter(window_seconds=300, max_count=5, max_keys=100)

        # Fill with many keys
        for i in range(200):
            rl.allow(f"key_{i}")

        start = time.monotonic()
        rl.cleanup()
        elapsed = time.monotonic() - start

        print(f"\nRate limiter cleanup: {elapsed * 1000:.1f}ms for 200 keys")
        assert elapsed < 1.0, "Cleanup took too long"
        # After cleanup, should be at or below max_keys
        assert len(rl._timestamps) <= 100


class TestDBBatchPerformance:
    @pytest.mark.asyncio
    async def test_db_batch_insert_events(self, event_repo):
        """Measure event insert throughput: 1000 events."""
        start = time.monotonic()
        for i in range(1000):
            await event_repo.insert(
                engine="perf_test",
                severity="INFO",
                title=f"Perf Event {i}",
                description="Performance test event",
                source_ip=f"192.168.1.{i % 255}",
            )
        elapsed = time.monotonic() - start

        eps = 1000 / elapsed if elapsed > 0 else float("inf")
        print(f"\nEvent insert throughput: {eps:.0f} events/sec ({elapsed:.3f}s)")

        count = await event_repo.count()
        assert count == 1000

    @pytest.mark.asyncio
    async def test_db_batch_upsert_devices(self, device_repo):
        """Measure device batch upsert throughput: 1000 devices."""
        buffer = {}
        for i in range(1000):
            mac = f"aa:bb:{i // 256:02x}:{i % 256:02x}:00:01"
            buffer[mac] = {
                "ip": f"10.0.{i // 256}.{i % 256}",
                "hostname": f"host-{i}",
                "vendor": "TestVendor",
                "os_hint": "Linux",
                "bytes": 1024,
                "packets": 10,
            }

        start = time.monotonic()
        await device_repo.batch_upsert(buffer)
        elapsed = time.monotonic() - start

        dps = 1000 / elapsed if elapsed > 0 else float("inf")
        print(f"\nDevice batch upsert throughput: {dps:.0f} devices/sec ({elapsed:.3f}s)")

        count = await device_repo.count()
        assert count == 1000
