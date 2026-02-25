"""Tests for data exfiltration detection engine."""

from scapy.all import IP, TCP, Raw, Ether

from netwatcher.detection.engines.data_exfil import DataExfilEngine
from netwatcher.detection.models import Severity


def make_outbound(src_ip: str, dst_ip: str, payload_size: int = 100) -> Ether:
    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=54321, dport=443)
        / Raw(load=b"x" * payload_size)
    )


class TestDataExfilEngine:
    def setup_method(self):
        self.engine = DataExfilEngine({
            "enabled": True,
            "byte_threshold": 1000,  # 1KB for testing
            "window_seconds": 3600,
            "dns_txt_size_threshold": 500,
        })

    def test_normal_traffic_no_alert(self):
        pkt = make_outbound("192.168.1.10", "8.8.8.8", 100)
        assert self.engine.analyze(pkt) is None
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_large_outbound_detected(self):
        src = "192.168.1.10"
        dst = "1.2.3.4"
        # Send enough data to exceed threshold (1KB)
        for _ in range(20):
            self.engine.analyze(make_outbound(src, dst, 100))

        alerts = self.engine.on_tick(0)
        exfil = [a for a in alerts if "Exfiltration" in a.title]
        assert len(exfil) == 1
        assert exfil[0].source_ip == src
        assert exfil[0].dest_ip == dst

    def test_internal_to_internal_ignored(self):
        for _ in range(20):
            self.engine.analyze(make_outbound("192.168.1.10", "192.168.1.20", 100))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_below_threshold_no_alert(self):
        self.engine.analyze(make_outbound("192.168.1.10", "1.2.3.4", 100))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0
