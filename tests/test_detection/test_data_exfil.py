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
        # Current engine config: outbound_threshold_mb (in MB), window_seconds
        # Use a very small threshold for testing: 0 MB means threshold_bytes = 0
        # Actually we need a value that 20 * ~154 bytes can exceed.
        # 20 packets * ~154 bytes each = ~3080 bytes = ~0.003 MB
        # We can't set outbound_threshold_mb to a fraction since it's int type.
        # Let's use outbound_threshold_mb=0 which would mean 0 bytes threshold -- but that would alert on everything.
        # Better approach: set to 1 MB and send enough data to exceed it.
        # Actually the engine stores: config.get("outbound_threshold_mb", 50) * 1024 * 1024
        # We need to work with MB. Let's just monkey-patch _threshold_bytes after init.
        self.engine = DataExfilEngine({
            "enabled": True,
            "outbound_threshold_mb": 50,
            "window_seconds": 3600,
        })
        # Override threshold to 1000 bytes for testing
        self.engine._threshold_bytes = 1000

    def test_normal_traffic_no_alert(self):
        pkt = make_outbound("192.168.1.10", "8.8.8.8", 100)
        assert self.engine.analyze(pkt) is None
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_large_outbound_detected(self):
        src = "192.168.1.10"
        dst = "1.2.3.4"
        # Send enough data to exceed threshold (1000 bytes)
        # Each packet is ~154 bytes (headers + 100 byte payload)
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
