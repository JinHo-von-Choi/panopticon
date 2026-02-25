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


class TestHoneypotDetection:
    def setup_method(self):
        self.engine = RansomwareLateralEngine(_CFG)  # honeypot_ips=["10.0.0.99"]

    def test_access_to_honeypot_fires_critical(self):
        pkt = make_syn("192.168.1.10", "10.0.0.99", 445)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert "honeypot" in alert.title.lower() or "Honeypot" in alert.title

    def test_normal_traffic_no_alert(self):
        pkt = make_syn("192.168.1.10", "192.168.1.20", 445)
        assert self.engine.analyze(pkt) is None

    def test_honeypot_as_source_fires_critical(self):
        """허니팟 IP가 출발지인 경우도 탐지 (허니팟이 피벗에 사용되는 상황)."""
        pkt = make_syn("10.0.0.99", "192.168.1.50", 80)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL

    def test_honeypot_cooldown_suppresses_duplicate(self):
        """동일 소스에서 쿨다운 내 재접근은 알림을 중복 발생시키지 않는다."""
        pkt = make_syn("192.168.1.10", "10.0.0.99", 445)
        first = self.engine.analyze(pkt)
        assert first is not None
        second = self.engine.analyze(pkt)
        assert second is None  # 쿨다운 적용

    def test_empty_honeypot_list_no_alert(self):
        cfg = {**_CFG, "honeypot_ips": []}
        engine = RansomwareLateralEngine(cfg)
        pkt = make_syn("192.168.1.10", "10.0.0.99", 445)
        assert engine.analyze(pkt) is None
