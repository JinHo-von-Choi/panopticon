"""Tests for port scan detection engine."""

import time

from scapy.all import IP, TCP, Ether

from netwatcher.detection.engines.port_scan import PortScanEngine
from netwatcher.detection.models import Severity


def make_syn(src_ip: str, dst_ip: str, dst_port: int) -> Ether:
    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=54321, dport=dst_port, flags="S")
    )


class TestPortScanEngine:
    def setup_method(self):
        # Current engine config keys: threshold, window_seconds, stealth_threshold
        self.engine = PortScanEngine({
            "enabled": True,
            "window_seconds": 60,
            "threshold": 5,  # lower threshold for testing
            "stealth_threshold": 3,
        })

    def test_single_syn_no_alert(self):
        pkt = make_syn("10.0.0.1", "10.0.0.2", 80)
        assert self.engine.analyze(pkt) is None
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_port_scan_detected(self):
        # Use truly external IP to avoid 3x internal multiplier
        # (is_private_ip covers RFC 1918, TEST-NET, etc.)
        src = "8.8.8.8"
        dst = "10.0.0.2"

        # Send SYN to 10 different ports (threshold=5)
        for port in range(1, 11):
            self.engine.analyze(make_syn(src, dst, port))

        alerts = self.engine.on_tick(0)
        assert len(alerts) == 1
        assert "Port Scan" in alerts[0].title
        assert alerts[0].source_ip == src

    def test_same_port_no_scan(self):
        src = "8.8.8.8"
        dst = "10.0.0.2"

        # Same port many times is NOT a scan
        for _ in range(20):
            self.engine.analyze(make_syn(src, dst, 80))

        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_alerted_cooldown(self):
        """After alerting, same pair should not re-alert within cooldown (window_seconds)."""
        src = "8.8.8.8"
        dst = "10.0.0.2"

        for port in range(1, 11):
            self.engine.analyze(make_syn(src, dst, port))
        alerts1 = self.engine.on_tick(0)
        assert len(alerts1) == 1

        # More ports scanned but within cooldown (window_seconds)
        for port in range(11, 21):
            self.engine.analyze(make_syn(src, dst, port))
        alerts2 = self.engine.on_tick(0)
        assert len(alerts2) == 0

    def test_confidence_in_metadata(self):
        """Port scan alerts should include confidence score."""
        src = "8.8.8.8"
        dst = "10.0.0.2"
        for port in range(1, 11):
            self.engine.analyze(make_syn(src, dst, port))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 1
        # confidence is a top-level Alert field
        assert alerts[0].confidence >= 0.6

    def test_max_connections_eviction(self):
        """Engine tracks scans per source IP in _scans dict."""
        engine = PortScanEngine({
            "enabled": True,
            "window_seconds": 60,
            "threshold": 5,
            "stealth_threshold": 3,
        })
        # Add connections from 4 different sources
        for i in range(4):
            engine.analyze(make_syn(f"8.8.{i}.1", "10.0.0.100", 80))
        # Each source IP should have entries
        assert len(engine._scans) == 4
