"""Tests for DHCP spoofing detection engine."""

from scapy.all import BOOTP, DHCP, IP, UDP, Ether

from netwatcher.detection.engines.dhcp_spoof import DHCPSpoofEngine
from netwatcher.detection.models import Severity


def make_dhcp_offer(server_ip: str, server_mac: str = "aa:bb:cc:00:00:01") -> Ether:
    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2)
        / DHCP(options=[("message-type", 2), "end"])  # OFFER
    )


def make_dhcp_discover(client_mac: str) -> Ether:
    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1)
        / DHCP(options=[("message-type", 1), "end"])  # DISCOVER
    )


class TestDHCPSpoofEngine:
    def setup_method(self):
        self.engine = DHCPSpoofEngine({
            "enabled": True,
            "starvation_threshold": 5,
            "starvation_window_seconds": 60,
        })

    def test_learns_legitimate_server(self):
        pkt = make_dhcp_offer("192.168.1.1")
        alert = self.engine.analyze(pkt)
        assert alert is None
        assert "192.168.1.1" in self.engine._known_servers

    def test_detects_rogue_server(self):
        # Learn legitimate server
        self.engine.analyze(make_dhcp_offer("192.168.1.1"))

        # Rogue server appears
        alert = self.engine.analyze(make_dhcp_offer("192.168.1.99", "dd:ee:ff:00:00:01"))
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "Rogue" in alert.title

    def test_starvation_detection(self):
        # Send many DISCOVERs from different MACs
        for i in range(10):
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            self.engine.analyze(make_dhcp_discover(mac))

        alerts = self.engine.on_tick(0)
        starv = [a for a in alerts if "Starvation" in a.title]
        assert len(starv) == 1

    def test_no_starvation_few_discovers(self):
        for i in range(3):
            mac = f"aa:bb:cc:dd:ee:{i:02x}"
            self.engine.analyze(make_dhcp_discover(mac))
        alerts = self.engine.on_tick(0)
        assert len(alerts) == 0
