"""Tests for traffic anomaly detection engine."""

import time
from unittest.mock import patch

from scapy.all import ARP, IP, TCP, Ether

from netwatcher.detection.engines.traffic_anomaly import (
    TrafficAnomalyEngine,
    _WelfordStats,
)
from netwatcher.detection.models import Severity


def _make_tcp_packet(
    src_mac: str = "aa:bb:cc:dd:ee:01",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "1.2.3.4",
    size: int = 100,
) -> Ether:
    payload_size = max(0, size - 54)  # Ether(14) + IP(20) + TCP(20)
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=80, flags="PA")
        / (b"\x00" * payload_size)
    )


def _make_arp_packet(src_mac: str, src_ip: str) -> Ether:
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=src_mac, psrc=src_ip)
    )


class TestWelfordStats:
    def test_initial_state(self):
        stats = _WelfordStats()
        assert stats.count == 0
        assert stats.mean == 0.0
        assert stats.variance == 0.0
        assert stats.stddev == 0.0

    def test_single_value(self):
        stats = _WelfordStats()
        stats.update(10.0)
        assert stats.count == 1
        assert stats.mean == 10.0
        assert stats.variance == 0.0

    def test_multiple_values(self):
        stats = _WelfordStats()
        for v in [10.0, 20.0, 30.0]:
            stats.update(v)
        assert stats.count == 3
        assert abs(stats.mean - 20.0) < 0.001
        assert stats.stddev > 0

    def test_constant_values_zero_variance(self):
        stats = _WelfordStats()
        for _ in range(10):
            stats.update(5.0)
        assert abs(stats.mean - 5.0) < 0.001
        assert abs(stats.variance) < 0.001


class TestTrafficAnomalyEngine:
    def setup_method(self):
        self.engine = TrafficAnomalyEngine({
            "enabled": True,
            "volume_threshold_multiplier": 3.0,
            "min_baseline_bytes": 100,
            "warmup_ticks": 5,
            "z_score_threshold": 3.0,
            "host_eviction_seconds": 86400,
            "max_tracked_hosts": 50000,
        })

    def test_new_device_alert(self):
        pkt = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01", src_ip="192.168.1.10")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "New Device" in alert.title
        assert alert.source_mac == "aa:bb:cc:dd:ee:01"

    def test_known_device_no_alert(self):
        pkt = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01")
        self.engine.analyze(pkt)  # First time: learn

        pkt2 = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01")
        alert = self.engine.analyze(pkt2)
        assert alert is None

    def test_broadcast_mac_ignored(self):
        pkt = Ether(src="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="1.2.3.4") / TCP()
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_arp_device_detection(self):
        pkt = _make_arp_packet("aa:bb:cc:dd:ee:02", "192.168.1.20")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "New Device" in alert.title

    def test_volume_anomaly_z_score(self):
        """After warmup, a traffic spike should trigger a z-score based anomaly."""
        engine = TrafficAnomalyEngine({
            "enabled": True,
            "volume_threshold_multiplier": 3.0,
            "min_baseline_bytes": 100,
            "warmup_ticks": 5,
            "z_score_threshold": 2.0,
        })
        src_ip = "192.168.1.10"
        # Warmup: establish baseline with slight variation (needed for stddev > 0)
        for i in range(10):
            size = 180 + (i % 3) * 20  # 180, 200, 220 cycle
            pkt = _make_tcp_packet(src_ip=src_ip, size=size)
            engine.analyze(pkt)
            engine.on_tick(0)

        # Now send a massive traffic spike (100x normal in single tick)
        for _ in range(100):
            pkt = _make_tcp_packet(src_ip=src_ip, size=2000)
            engine.analyze(pkt)

        alerts = engine.on_tick(0)
        anomaly_alerts = [a for a in alerts if "Volume" in a.title]
        assert len(anomaly_alerts) >= 1
        assert anomaly_alerts[0].severity == Severity.WARNING
        assert anomaly_alerts[0].metadata["z_score"] > 2.0

    def test_no_anomaly_during_warmup(self):
        """Traffic spikes during warmup should not trigger alerts."""
        src_ip = "192.168.1.10"
        # Only 2 ticks (below warmup_ticks=5)
        for i in range(2):
            pkt = _make_tcp_packet(src_ip=src_ip, size=200)
            self.engine.analyze(pkt)
            self.engine.on_tick(0)

        # Spike
        for _ in range(50):
            pkt = _make_tcp_packet(src_ip=src_ip, size=5000)
            self.engine.analyze(pkt)

        alerts = self.engine.on_tick(0)
        anomaly_alerts = [a for a in alerts if "Volume" in a.title]
        assert len(anomaly_alerts) == 0

    def test_normal_traffic_no_anomaly(self):
        """Consistent traffic should not produce anomaly alerts."""
        src_ip = "192.168.1.10"
        for _ in range(15):
            for _ in range(5):
                pkt = _make_tcp_packet(src_ip=src_ip, size=500)
                self.engine.analyze(pkt)
            alerts = self.engine.on_tick(0)
            anomaly_alerts = [a for a in alerts if "Volume" in a.title]
            assert len(anomaly_alerts) == 0

    def test_bytes_tracked_per_host(self):
        pkt = _make_tcp_packet(src_ip="192.168.1.10", size=500)
        self.engine.analyze(pkt)
        assert self.engine._host_bytes["192.168.1.10"] > 0

    def test_host_bytes_cleared_on_tick(self):
        pkt = _make_tcp_packet(src_ip="192.168.1.10", size=500)
        self.engine.analyze(pkt)
        self.engine.on_tick(0)
        assert self.engine._host_bytes.get("192.168.1.10", 0) == 0

    def test_eviction_of_stale_hosts(self):
        """Hosts not seen for eviction_seconds should be removed."""
        engine = TrafficAnomalyEngine({
            "enabled": True,
            "warmup_ticks": 5,
            "host_eviction_seconds": 100,
        })
        now = time.time()
        with patch("netwatcher.detection.engines.traffic_anomaly.time") as mock_time:
            mock_time.time.return_value = now
            pkt = _make_tcp_packet(src_ip="192.168.1.10")
            engine.analyze(pkt)
            engine.on_tick(0)

            # Advance time past eviction
            mock_time.time.return_value = now + 200
            # Trigger eviction (tick_count must be multiple of 60)
            engine._tick_count = 59
            engine.on_tick(0)

        assert "192.168.1.10" not in engine._host_last_seen
        assert "192.168.1.10" not in engine._host_stats

    def test_shutdown_clears_state(self):
        pkt = _make_tcp_packet()
        self.engine.analyze(pkt)
        self.engine.on_tick(0)

        self.engine.shutdown()
        assert len(self.engine._host_stats) == 0
        assert len(self.engine._known_macs) == 0
