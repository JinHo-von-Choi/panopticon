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
        assert "honeypot" in alert.title.lower()

    def test_normal_traffic_no_alert(self):
        pkt = make_syn("192.168.1.10", "192.168.1.20", 445)
        assert self.engine.analyze(pkt) is None

    def test_honeypot_as_source_fires_critical(self):
        """허니팟 IP가 출발지인 경우도 탐지 (허니팟이 피벗에 사용되는 상황)."""
        pkt = make_syn("10.0.0.99", "192.168.1.50", 80)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.CRITICAL
        assert alert.source_ip == "10.0.0.99"  # 허니팟 IP가 공격 주체로 기록

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


class TestSmbWormScan:
    def setup_method(self):
        self.engine = RansomwareLateralEngine({
            **_CFG,
            "smb_scan_threshold": 5,
            "smb_scan_window_seconds": 30,
            "honeypot_ips": [],
        })

    def _send_smb_syns(self, src: str, dst_prefix: str, count: int):
        for i in range(count):
            pkt = make_syn(src, f"{dst_prefix}.{10 + i}", 445)
            self.engine.analyze(pkt)

    def test_below_threshold_no_alert(self):
        self._send_smb_syns("192.168.1.10", "192.168.1", 4)
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 0

    def test_at_threshold_fires_warning(self):
        self._send_smb_syns("192.168.1.10", "192.168.1", 5)
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 1
        assert smb_alerts[0].severity == Severity.WARNING
        assert smb_alerts[0].source_ip == "192.168.1.10"

    def test_same_dst_repeated_does_not_trigger(self):
        """동일 대상 반복은 고유 호스트 수를 늘리지 않는다."""
        src = "192.168.1.10"
        for _ in range(10):
            self.engine.analyze(make_syn(src, "192.168.1.20", 445))
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 0

    def test_external_src_ignored(self):
        """외부 IP 출발 SMB 스캔은 무시한다 (경계 방화벽 영역)."""
        for i in range(10):
            self.engine.analyze(make_syn("8.8.8.8", f"192.168.1.{10 + i}", 445))
        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_non_445_port_ignored(self):
        for i in range(5):
            self.engine.analyze(make_syn("192.168.1.11", f"192.168.1.{20 + i}", 80))
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len([a for a in smb_alerts if a.source_ip == "192.168.1.11"]) == 0

    def test_alert_metadata_includes_target_count(self):
        self._send_smb_syns("192.168.1.10", "192.168.1", 7)
        alerts = self.engine.on_tick(time.time())
        smb = next(a for a in alerts if "SMB" in a.title)
        assert smb.metadata.get("unique_targets") == 7

    def test_cooldown_suppresses_second_alert(self):
        """쿨다운 내 동일 소스의 중복 알림을 억제한다."""
        self._send_smb_syns("192.168.1.10", "192.168.1", 5)
        self.engine.on_tick(time.time())  # 첫 알림

        # 더 보내도 쿨다운 내에서는 재알림 없음
        self._send_smb_syns("192.168.1.10", "192.168.2", 5)
        alerts2 = self.engine.on_tick(time.time())
        smb_alerts2 = [a for a in alerts2 if "SMB" in a.title]
        assert len(smb_alerts2) == 0

    def test_whitelisted_src_no_alert(self):
        """화이트리스트에 등록된 IP는 SMB 스캔 알림을 발생시키지 않는다."""
        from netwatcher.detection.whitelist import Whitelist
        wl = Whitelist({"ips": ["192.168.1.10"], "ip_ranges": [], "macs": [],
                        "domains": [], "domain_suffixes": []})
        self.engine.set_whitelist(wl)
        self._send_smb_syns("192.168.1.10", "192.168.1", 10)
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 0
