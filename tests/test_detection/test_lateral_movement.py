"""Tests for lateral movement detection engine."""

from scapy.all import IP, TCP, Ether

from netwatcher.detection.engines.lateral_movement import LateralMovementEngine
from netwatcher.detection.models import Severity


def make_syn(src_ip: str, dst_ip: str, dst_port: int) -> Ether:
    return Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=54321, dport=dst_port, flags="S")


class TestLateralMovementEngine:
    def setup_method(self):
        self.engine = LateralMovementEngine({
            "enabled": True,
            "lateral_ports": [22, 445, 3389],
            "unique_host_threshold": 3,
            "window_seconds": 300,
            "chain_depth_threshold": 3,
        })

    def test_single_connection_no_alert(self):
        pkt = make_syn("192.168.1.10", "192.168.1.20", 22)
        assert self.engine.analyze(pkt) is None
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_lateral_movement_detected(self):
        src = "192.168.1.10"
        for i in range(5):
            self.engine.analyze(make_syn(src, f"192.168.1.{20 + i}", 22))

        alerts = self.engine.on_tick(0)
        lateral = [a for a in alerts if "Lateral Movement" in a.title]
        assert len(lateral) == 1
        assert lateral[0].source_ip == src

    def test_external_ip_ignored(self):
        # External -> internal should not be tracked
        pkt = make_syn("8.8.8.8", "192.168.1.10", 22)
        assert self.engine.analyze(pkt) is None

    def test_non_lateral_port_ignored(self):
        src = "192.168.1.10"
        for i in range(5):
            self.engine.analyze(make_syn(src, f"192.168.1.{20 + i}", 80))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0

    def test_same_target_no_alert(self):
        src = "192.168.1.10"
        for _ in range(10):
            self.engine.analyze(make_syn(src, "192.168.1.20", 22))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0  # only 1 unique host
