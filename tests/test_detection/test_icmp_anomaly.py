"""Tests for ICMP anomaly detection engine."""

from scapy.all import ICMP, IP, Ether

from netwatcher.detection.engines.icmp_anomaly import ICMPAnomalyEngine
from netwatcher.detection.models import Severity


def make_icmp(src_ip: str, dst_ip: str, icmp_type: int = 8, icmp_code: int = 0) -> Ether:
    return Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type, code=icmp_code)


class TestICMPAnomalyEngine:
    def setup_method(self):
        # Current engine config: sweep_threshold, flood_threshold, window_seconds
        self.engine = ICMPAnomalyEngine({
            "enabled": True,
            "sweep_threshold": 5,
            "window_seconds": 30,
            "flood_threshold": 10,
        })

    def test_normal_ping_no_alert(self):
        pkt = make_icmp("10.0.0.1", "10.0.0.2")
        assert self.engine.analyze(pkt) is None

    def test_suspicious_icmp_type(self):
        """ICMP type 5 (Redirect) is in the allowed set (0,3,5,8,11), so no alert.
        Use an uncommon type like 13 (Timestamp) to trigger suspicious type detection."""
        pkt = make_icmp("10.0.0.1", "10.0.0.2", icmp_type=13)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "Suspicious" in alert.title or "ICMP" in alert.title

    def test_ping_sweep_detected(self):
        src = "10.0.0.1"
        for i in range(10):
            self.engine.analyze(make_icmp(src, f"10.0.0.{i + 10}"))

        alerts = self.engine.on_tick(0)
        sweep_alerts = [a for a in alerts if "Sweep" in a.title]
        assert len(sweep_alerts) == 1
        assert sweep_alerts[0].source_ip == src

    def test_icmp_flood_detected(self):
        src = "10.0.0.1"
        dst = "10.0.0.2"
        for _ in range(15):
            self.engine.analyze(make_icmp(src, dst))

        alerts = self.engine.on_tick(0)
        flood_alerts = [a for a in alerts if "Flood" in a.title]
        assert len(flood_alerts) == 1

    def test_no_false_positive_few_pings(self):
        for i in range(3):
            self.engine.analyze(make_icmp("10.0.0.1", f"10.0.0.{i + 10}"))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0
