# tests/test_detection/test_ransomware_lateral.py
"""Tests for ransomware lateral movement detection engine."""
from __future__ import annotations

import time
from scapy.all import Ether, IP, TCP

from netwatcher.detection.engines.ransomware_lateral import RansomwareLateralEngine
from netwatcher.detection.models import Severity


def make_syn(src: str, dst: str, dport: int) -> Ether:
    return Ether() / IP(src=src, dst=dst) / TCP(sport=54321, dport=dport, flags="S")


def make_udp(src: str, dst: str, dport: int) -> Ether:
    from scapy.all import UDP
    return Ether() / IP(src=src, dst=dst) / UDP(sport=54321, dport=dport)


_CFG = {
    "enabled":                  True,
    "smb_scan_window_seconds":  30,
    "smb_scan_threshold":       5,
    "rdp_brute_window_seconds": 60,
    "rdp_brute_threshold":      5,
    "alert_cooldown_seconds":   300,
    "honeypot_ips":             ["10.0.0.99"],
    "max_tracked_sources":      10000,
}


class TestImport:
    def test_engine_instantiates(self):
        engine = RansomwareLateralEngine(_CFG)
        assert engine.name == "ransomware_lateral"
        assert engine.enabled is True
