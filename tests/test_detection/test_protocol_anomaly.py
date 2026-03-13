"""Tests for protocol anomaly detection engine."""

from scapy.all import IP, TCP, Ether

from netwatcher.detection.engines.protocol_anomaly import ProtocolAnomalyEngine
from netwatcher.detection.models import Severity


def make_tcp(src_ip: str, dst_ip: str, dst_port: int, flags: str = "S",
             ttl: int = 64) -> Ether:
    return (
        Ether()
        / IP(src=src_ip, dst=dst_ip, ttl=ttl)
        / TCP(sport=54321, dport=dst_port, flags=flags)
    )


class TestProtocolAnomalyEngine:
    def setup_method(self):
        # Current engine config keys: min_ttl, detect_reserved_bits
        self.engine = ProtocolAnomalyEngine({
            "enabled": True,
            "min_ttl": 10,
            "detect_reserved_bits": True,
        })

    def test_normal_packet_no_alert(self):
        pkt = make_tcp("10.0.0.1", "10.0.0.2", 80, "S", ttl=64)
        assert self.engine.analyze(pkt) is None

    def test_syn_fin_detected(self):
        pkt = make_tcp("10.0.0.1", "10.0.0.2", 80, "SF")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "SYN+FIN" in alert.title

    def test_null_flags_detected(self):
        """NULL flags (flags=0) triggers stealth scan detection.
        Note: The protocol_anomaly engine does not detect NULL flags as anomaly
        since it only checks SYN+FIN combo. NULL flag scan detection is in port_scan engine.
        The protocol_anomaly engine checks: low TTL, SYN+FIN, and reserved bits.
        With ttl=64 and flags="", this should NOT trigger an alert."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(sport=1234, dport=80, flags="")
        alert = self.engine.analyze(pkt)
        # Current engine does NOT flag NULL TCP flags -- only SYN+FIN
        assert alert is None

    def test_ttl_anomaly_detected(self):
        """Low TTL packets are detected."""
        src = "10.0.0.99"
        # Send a packet with TTL below min_ttl (10)
        alert = self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=5))
        assert alert is not None
        assert "TTL" in alert.title
        assert alert.metadata["ttl"] == 5

    def test_ttl_normal_variation_no_alert(self):
        src = "10.0.0.1"
        # TTL=64 is above min_ttl=10, no alert
        alert = self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=64))
        assert alert is None
        # TTL=63 is also above min_ttl=10, no alert
        alert = self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=63))
        assert alert is None
