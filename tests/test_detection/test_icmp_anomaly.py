"""Tests for ICMP anomaly detection engine."""

from scapy.all import ICMP, IP, Ether

from netwatcher.detection.engines.icmp_anomaly import ICMPAnomalyEngine
from netwatcher.detection.models import Severity


def make_icmp(src_ip: str, dst_ip: str, icmp_type: int = 8, icmp_code: int = 0) -> Ether:
    return Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=icmp_type, code=icmp_code)


class TestICMPAnomalyEngine:
    def setup_method(self):
        self.engine = ICMPAnomalyEngine({
            "enabled": True,
            "ping_sweep_threshold": 5,
            "ping_sweep_window_seconds": 30,
            "flood_threshold": 10,
            "flood_window_seconds": 1,
        })

    def test_normal_ping_no_alert(self):
        pkt = make_icmp("10.0.0.1", "10.0.0.2")
        assert self.engine.analyze(pkt) is None

    def test_suspicious_icmp_type(self):
        pkt = make_icmp("10.0.0.1", "10.0.0.2", icmp_type=5)  # Redirect
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Redirect" in alert.title

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
