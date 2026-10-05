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
    """캡처 경로와 동일한 형태의 패킷을 만든다.

    스니퍼가 넘기는 패킷은 항상 wire bytes에서 파싱된 상태다. 조립만 한 패킷은
    len() 호출마다 scapy가 전체를 재직렬화하므로, 그대로 쓰면 엔진 처리량이
    아니라 직렬화 비용을 측정하게 된다.
    """
    packet = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / \
             IP(src=src_ip, dst=dst_ip) / \
             TCP(sport=sport, dport=dport, flags="S")
    return Ether(bytes(packet))


class TestEngineThroughput:
    def test_engine_throughput(self, config):
        """Measure throughput: 10000 packets through EngineRegistry.

        워밍업 패스를 하나 둔다. 첫 패킷의 처리에는 엔진 초기 상태 생성
        (윈도우 버퍼, 초기 지표)이 섞이는데, 그것을 시간에 포함하면 측정값이
        코드 상태가 아니라 **측정 순서** 를 재게 된다.

        기준(1000 pps)은 낮추지 않는다. 이 테스트의 목적은 엔진이 느려졌는지
        를 잡는 것이고, 느려진 걸 통과시키기 위한 수치를 고치는 것은
        측정 고기를 고쳐 먹는 것이다. 대신 측정에서 순서 효과를 제거한다.
        """
        registry = EngineRegistry(config)
        registry.discover_and_register()

        packets = [
            _make_tcp_packet(dport=80 + (i % 100))
            for i in range(10000)
        ]

        # 워밍업 — 측정 대상이 아니다
        for pkt in packets[:200]:
            registry.process_packet(pkt)

        start = time.monotonic()
        total_alerts = 0
        for pkt in packets:
            alerts = registry.process_packet(pkt)
            total_alerts += len(alerts)
        elapsed = time.monotonic() - start

        pps = len(packets) / elapsed if elapsed > 0 else float("inf")
        print(f"\nEngine throughput: {pps:.0f} packets/sec ({elapsed:.3f}s for {len(packets)} packets, {total_alerts} alerts)")

        # 기준(1000 pps)은 낮추지 않는다. 이 테스트의 목적은 엔진이 느려졌는지
        # 를 잡는 것이고, 느려진 걸 통과시키려고 수치를 고치는 것은 측정 고기를
        # 고쳐 먹는 것이다. 대신 실패하면 원인을 추측하지 않게 값을 그대로 남긴다.
        #
        # 주의: **벽시계 측정**이다. 같은 코드라도 머신이 바쁘면 떨어진다.
        # 고립 실행과 전체 스위트 동시 실행에서 결과가 다르면 먼저 부하를
        # 의심한다 — 코드가 느려진 것이 아닐 수 있다.
        assert pps > 1000, (
            f"Engine throughput too low: {pps:.0f} pps "
            f"({elapsed:.3f}s / {len(packets)} packets). 기준 1000 pps. "
            f"고립 실행 값과 비교해 부하 영향인지 코드 회귀인지 구분한다."
        )

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
