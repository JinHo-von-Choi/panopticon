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
        self.engine = ProtocolAnomalyEngine({
            "enabled": True,
            "ttl_change_threshold": 10,
            "min_ttl_samples": 5,
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
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "NULL" in alert.title

    def test_ttl_anomaly_detected(self):
        src = "10.0.0.1"
        # Build baseline with TTL=64
        for _ in range(6):
            self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=64))

        # Sudden TTL change to 128
        alert = self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=128))
        assert alert is not None
        assert "TTL" in alert.title
        assert alert.metadata["ttl_diff"] >= 10

    def test_ttl_normal_variation_no_alert(self):
        src = "10.0.0.1"
        for _ in range(6):
            self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=64))
        # Small TTL change
        alert = self.engine.analyze(make_tcp(src, "10.0.0.2", 80, "S", ttl=63))
        assert alert is None
