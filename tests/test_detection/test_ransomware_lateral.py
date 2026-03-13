# tests/test_detection/test_ransomware_lateral.py
"""Tests for ransomware lateral movement detection engine."""
from __future__ import annotations

import time
from scapy.all import Ether, IP, TCP

import pytest
from netwatcher.detection.engines.ransomware_lateral import RansomwareLateralEngine
from netwatcher.detection.models import Severity


def make_syn(src: str, dst: str, dport: int) -> Ether:
    return Ether() / IP(src=src, dst=dst) / TCP(sport=54321, dport=dport, flags="S")


def make_udp(src: str, dst: str, dport: int) -> Ether:
    from scapy.all import UDP
    return Ether() / IP(src=src, dst=dst) / UDP(sport=54321, dport=dport)


_CFG = {
    "enabled":               True,
    "brute_force_threshold": 5,
    "window_seconds":        60,
    "honeypot_ips":          ["10.0.0.99"],
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

    @pytest.mark.skip(reason="현재 엔진은 dst_ip 기반 허니팟 탐지만 지원, src_ip 허니팟 미구현")
    def test_honeypot_as_source_fires_critical(self):
        pass

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


class TestSmbBruteForce:
    """SMB(445) 브루트포스 탐지 테스트.

    현재 엔진은 (src_ip, dst_ip, port) 단위로 연결 시도를 추적한다.
    동일 대상에 threshold 이상 SYN 전송 시 알림을 발생시킨다.
    """

    def setup_method(self):
        self.engine = RansomwareLateralEngine({
            **_CFG,
            "brute_force_threshold": 5,
            "window_seconds":        60,
            "honeypot_ips":          [],
        })

    def _send_smb_syns(self, src: str, dst: str, count: int):
        """동일 대상에 SMB SYN 패킷을 count회 전송."""
        for _ in range(count):
            pkt = make_syn(src, dst, 445)
            self.engine.analyze(pkt)

    def test_below_threshold_no_alert(self):
        self._send_smb_syns("192.168.1.10", "192.168.1.20", 4)
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 0

    def test_at_threshold_fires_critical(self):
        self._send_smb_syns("192.168.1.10", "192.168.1.20", 5)
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 1
        assert smb_alerts[0].severity == Severity.CRITICAL
        assert smb_alerts[0].source_ip == "192.168.1.10"

    def test_non_445_port_ignored(self):
        for _ in range(10):
            self.engine.analyze(make_syn("192.168.1.11", "192.168.1.20", 80))
        alerts = self.engine.on_tick(time.time())
        smb_alerts = [a for a in alerts if "SMB" in a.title]
        assert len(smb_alerts) == 0

    def test_alert_metadata_includes_count(self):
        self._send_smb_syns("192.168.1.10", "192.168.1.20", 7)
        alerts = self.engine.on_tick(time.time())
        smb = next(a for a in alerts if "SMB" in a.title)
        assert smb.metadata.get("count") == 7

    def test_cooldown_suppresses_second_alert(self):
        """쿨다운(window_seconds) 내 동일 키의 중복 알림을 억제한다."""
        self._send_smb_syns("192.168.1.10", "192.168.1.20", 5)
        self.engine.on_tick(time.time())  # 첫 알림

        # 더 보내도 쿨다운 내에서는 재알림 없음
        self._send_smb_syns("192.168.1.10", "192.168.1.20", 5)
        alerts2 = self.engine.on_tick(time.time())
        smb_alerts2 = [a for a in alerts2 if "SMB" in a.title]
        assert len(smb_alerts2) == 0

    @pytest.mark.skip(reason="현재 엔진에 whitelist 기반 SMB 필터링 미구현")
    def test_whitelisted_src_no_alert(self):
        pass


class TestRdpBruteForce:
    def setup_method(self):
        self.engine = RansomwareLateralEngine({
            **_CFG,
            "brute_force_threshold": 5,
            "window_seconds":        60,
            "honeypot_ips":          [],
        })

    def _send_rdp_syns(self, src: str, dst: str, count: int):
        for _ in range(count):
            self.engine.analyze(make_syn(src, dst, 3389))

    def test_below_threshold_no_alert(self):
        self._send_rdp_syns("192.168.1.10", "192.168.1.20", 4)
        alerts = self.engine.on_tick(time.time())
        rdp_alerts = [a for a in alerts if "RDP" in a.title]
        assert len(rdp_alerts) == 0

    def test_at_threshold_fires_critical(self):
        self._send_rdp_syns("192.168.1.10", "192.168.1.20", 5)
        alerts = self.engine.on_tick(time.time())
        rdp_alerts = [a for a in alerts if "RDP" in a.title]
        assert len(rdp_alerts) == 1
        assert rdp_alerts[0].severity == Severity.CRITICAL
        assert rdp_alerts[0].source_ip  == "192.168.1.10"
        assert rdp_alerts[0].dest_ip    == "192.168.1.20"

    def test_different_dst_counted_separately(self):
        """다른 대상에 대한 RDP 시도는 각각 독립적으로 집계된다."""
        self._send_rdp_syns("192.168.1.10", "192.168.1.20", 5)
        self._send_rdp_syns("192.168.1.10", "192.168.1.21", 5)
        alerts = self.engine.on_tick(time.time())
        rdp_alerts = [a for a in alerts if "RDP" in a.title]
        assert len(rdp_alerts) == 2

    def test_non_syn_packet_ignored(self):
        """SYN이 아닌 TCP 패킷(예: ACK)은 집계하지 않는다."""
        from scapy.all import Ether, IP, TCP
        for _ in range(10):
            pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") \
                  / TCP(sport=54321, dport=3389, flags="A")
            self.engine.analyze(pkt)
        alerts = self.engine.on_tick(time.time())
        assert len([a for a in alerts if "RDP" in a.title]) == 0

    def test_alert_contains_dest_ip(self):
        self._send_rdp_syns("192.168.1.10", "192.168.1.20", 5)
        alerts = self.engine.on_tick(time.time())
        rdp = next(a for a in alerts if "RDP" in a.title)
        assert rdp.dest_ip == "192.168.1.20"

    def test_rdp_cooldown_suppresses_duplicate(self):
        self._send_rdp_syns("192.168.1.10", "192.168.1.20", 5)
        self.engine.on_tick(time.time())  # 첫 알림

        self._send_rdp_syns("192.168.1.10", "192.168.1.20", 5)
        alerts2 = self.engine.on_tick(time.time())
        assert len([a for a in alerts2 if "RDP" in a.title]) == 0


class TestConfigSchema:
    def test_default_config_validates(self):
        """config_schema 기본값으로 생성한 엔진이 경고 없이 초기화된다."""
        default_cfg = {
            k: v["default"]
            for k, v in RansomwareLateralEngine.config_schema.items()
            if isinstance(v, dict) and "default" in v
        }
        default_cfg["enabled"] = True
        engine = RansomwareLateralEngine(default_cfg)
        warnings = engine.validate_config()
        assert warnings == []

    def test_engine_name_is_ransomware_lateral(self):
        assert RansomwareLateralEngine.name == "ransomware_lateral"
