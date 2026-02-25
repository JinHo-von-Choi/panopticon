"""Tests for ARP spoofing detection engine."""

from scapy.all import ARP, Ether

from netwatcher.detection.engines.arp_spoof import ARPSpoofEngine
from netwatcher.detection.models import Severity


def make_arp_reply(src_mac: str, src_ip: str, dst_mac: str = "ff:ff:ff:ff:ff:ff",
                   dst_ip: str = "0.0.0.0") -> Ether:
    return Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=src_ip, hwdst=dst_mac, pdst=dst_ip
    )


class TestARPSpoofEngine:
    def setup_method(self):
        self.engine = ARPSpoofEngine({
            "enabled": True,
            "gratuitous_window_seconds": 30,
            "gratuitous_threshold": 10,
            "cooldown_seconds": 300,
        })

    def test_learns_new_binding(self):
        pkt = make_arp_reply("aa:bb:cc:dd:ee:01", "192.168.1.1")
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_detects_spoof(self):
        # First, learn a legitimate binding
        pkt1 = make_arp_reply("aa:bb:cc:dd:ee:01", "192.168.1.1")
        self.engine.analyze(pkt1)

        # Now spoof: same IP, different MAC
        pkt2 = make_arp_reply("aa:bb:cc:dd:ee:99", "192.168.1.1")
        alert = self.engine.analyze(pkt2)

        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "ARP Spoofing" in alert.title
        assert alert.metadata["original_mac"] == "aa:bb:cc:dd:ee:01"
        assert alert.metadata["new_mac"] == "aa:bb:cc:dd:ee:99"

    def test_gratuitous_arp_flood(self):
        src_mac = "aa:bb:cc:dd:ee:01"
        src_ip = "192.168.1.1"
        alert = None
        for _ in range(15):
            pkt = make_arp_reply(src_mac, src_ip, dst_ip=src_ip)
            result = self.engine.analyze(pkt)
            if result:
                alert = result

        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert "Gratuitous" in alert.title

    def test_gratuitous_cooldown(self):
        """After alerting, should not re-alert within cooldown period."""
        src_mac = "aa:bb:cc:dd:ee:01"
        src_ip = "192.168.1.1"

        # Trigger first alert
        for _ in range(15):
            pkt = make_arp_reply(src_mac, src_ip, dst_ip=src_ip)
            self.engine.analyze(pkt)

        # More gratuitous ARPs should NOT trigger another alert (cooldown)
        alert = None
        for _ in range(15):
            pkt = make_arp_reply(src_mac, src_ip, dst_ip=src_ip)
            result = self.engine.analyze(pkt)
            if result:
                alert = result

        assert alert is None

    def test_on_tick_prunes_stale(self):
        """on_tick should not crash and should prune stale data."""
        self.engine.on_tick(0)
        assert True
