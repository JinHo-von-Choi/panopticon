"""Tests for MAC spoofing detection engine."""

from scapy.all import ARP, IP, Ether

from netwatcher.detection.engines.mac_spoof import MACSpoofEngine
from netwatcher.detection.models import Severity


def make_ip_packet(src_mac: str, src_ip: str, dst_ip: str = "10.0.0.1") -> Ether:
    return Ether(src=src_mac) / IP(src=src_ip, dst=dst_ip)


class TestMACSpoofEngine:
    def setup_method(self):
        self.engine = MACSpoofEngine({
            "enabled": True,
            "max_ips_per_mac": 3,
            "ip_window_seconds": 300,
        })

    def test_normal_traffic_no_alert(self):
        # Use a globally unique MAC (bit 1 of first byte = 0)
        pkt = make_ip_packet("a8:bb:cc:dd:ee:01", "192.168.1.10")
        assert self.engine.analyze(pkt) is None

    def test_multi_ip_detected(self):
        mac = "a8:bb:cc:dd:ee:01"
        for i in range(5):
            self.engine.analyze(make_ip_packet(mac, f"192.168.1.{10 + i}"))

        alerts = self.engine.on_tick(0)
        clone_alerts = [a for a in alerts if "Cloning" in a.title]
        assert len(clone_alerts) == 1

    def test_locally_administered_mac(self):
        # MAC with locally administered bit set (0x02 in first byte)
        pkt = make_ip_packet("06:00:00:00:00:01", "192.168.1.10")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "Locally Administered" in alert.title

    def test_vm_mac_not_alerted(self):
        # VMware MAC (should not alert for locally administered)
        pkt = make_ip_packet("00:50:56:12:34:56", "192.168.1.10")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_few_ips_no_alert(self):
        mac = "a8:bb:cc:dd:ee:01"
        for i in range(2):
            self.engine.analyze(make_ip_packet(mac, f"192.168.1.{10 + i}"))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0
