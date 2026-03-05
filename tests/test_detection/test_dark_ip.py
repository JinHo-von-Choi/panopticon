"""다크 IP 탐지 엔진 테스트."""

from __future__ import annotations

import time
import unittest.mock as mock

import pytest
from scapy.all import ARP, IP, TCP, Ether, Packet

from netwatcher.detection.engines.dark_ip import DarkIPEngine, _ip_in_networks, _parse_networks
from netwatcher.detection.models import Severity


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------

def make_ip(src: str, dst: str) -> Packet:
    return Ether() / IP(src=src, dst=dst) / TCP(dport=80)


BASE_CONFIG = {
    "enabled": True,
    "monitored_networks": ["10.0.0.0/8"],
    "known_hosts": ["10.0.0.1", "10.0.0.2"],
    "learn_seconds": 0,        # 학습 기간 없음 — 즉시 탐지
    "cooldown_seconds": 3600,
    "auto_learn": True,
}


# ---------------------------------------------------------------------------
# _parse_networks / _ip_in_networks 단위 테스트
# ---------------------------------------------------------------------------

class TestParseNetworks:
    def test_parses_valid_cidr(self):
        nets = _parse_networks(["10.0.0.0/8", "192.168.0.0/16"])
        assert len(nets) == 2

    def test_skips_invalid_entry(self):
        nets = _parse_networks(["bad_cidr", "10.0.0.0/8"])
        assert len(nets) == 1

    def test_empty_list(self):
        assert _parse_networks([]) == []


class TestIpInNetworks:
    def setup_method(self):
        self.nets = _parse_networks(["10.0.0.0/8"])

    def test_ip_in_network(self):
        assert _ip_in_networks("10.1.2.3", self.nets) is True

    def test_ip_not_in_network(self):
        assert _ip_in_networks("192.168.1.1", self.nets) is False

    def test_invalid_ip(self):
        assert _ip_in_networks("not_an_ip", self.nets) is False

    def test_empty_networks_always_false(self):
        assert _ip_in_networks("10.0.0.1", []) is False


# ---------------------------------------------------------------------------
# DarkIPEngine 엔진 테스트
# ---------------------------------------------------------------------------

class TestDarkIPEngine:
    def setup_method(self):
        self.engine = DarkIPEngine(BASE_CONFIG)

    def test_no_monitored_networks_returns_none(self):
        engine = DarkIPEngine({**BASE_CONFIG, "monitored_networks": []})
        pkt = make_ip("10.0.0.5", "10.0.1.99")
        assert engine.analyze(pkt) is None

    def test_non_ip_packet_returns_none(self):
        pkt = Ether() / ARP()
        assert self.engine.analyze(pkt) is None

    def test_known_host_returns_none(self):
        # known_hosts에 명시된 IP는 정상
        pkt = make_ip("10.0.0.5", "10.0.0.1")
        assert self.engine.analyze(pkt) is None

    def test_dark_ip_returns_alert(self):
        pkt = make_ip("10.0.0.5", "10.0.1.99")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert alert.engine == "dark_ip"
        assert alert.source_ip == "10.0.0.5"
        assert alert.dest_ip == "10.0.1.99"

    def test_dark_ip_outside_monitored_returns_none(self):
        # 외부 인터넷 IP는 탐지 대상 아님
        pkt = make_ip("10.0.0.5", "8.8.8.8")
        assert self.engine.analyze(pkt) is None

    def test_auto_learn_src_ip(self):
        # 소스 IP는 자동 학습되어 이후 dst로 등장해도 정상
        src = "10.0.2.10"
        dst = "10.0.2.10"
        # 먼저 src로 보내서 학습
        pkt_src = make_ip(src, "10.0.0.1")  # known dst
        self.engine.analyze(pkt_src)
        # 이제 같은 IP가 dst로 등장
        pkt_dst = make_ip("10.0.0.5", dst)
        assert self.engine.analyze(pkt_dst) is None

    def test_auto_learn_disabled(self):
        engine = DarkIPEngine({**BASE_CONFIG, "auto_learn": False})
        src = "10.0.2.10"
        # src로 한 번 보내도 학습 안 됨
        pkt_src = make_ip(src, "10.0.0.1")
        engine.analyze(pkt_src)
        pkt_dst = make_ip("10.0.0.5", src)
        alert = engine.analyze(pkt_dst)
        assert alert is not None

    def test_cooldown_suppresses_duplicate(self):
        pkt = make_ip("10.0.0.5", "10.0.1.99")
        alert1 = self.engine.analyze(pkt)
        assert alert1 is not None
        alert2 = self.engine.analyze(pkt)
        assert alert2 is None

    def test_cooldown_zero_allows_repeat(self):
        engine = DarkIPEngine({**BASE_CONFIG, "cooldown_seconds": 0})
        pkt = make_ip("10.0.0.5", "10.0.1.99")
        assert engine.analyze(pkt) is not None
        assert engine.analyze(pkt) is not None

    def test_learn_period_suppresses_alert(self):
        engine = DarkIPEngine({**BASE_CONFIG, "learn_seconds": 3600})
        pkt = make_ip("10.0.0.5", "10.0.1.99")
        # 학습 기간 중에는 경고 없음
        assert engine.analyze(pkt) is None

    def test_learn_period_registers_dst_as_known(self):
        engine = DarkIPEngine({**BASE_CONFIG, "learn_seconds": 3600})
        dark_ip = "10.0.9.99"
        pkt = make_ip("10.0.0.5", dark_ip)
        engine.analyze(pkt)  # 학습 기간 중 — 등록됨
        # 학습 기간 종료 시뮬레이션
        engine._start_time -= 7200
        # 이제 해당 IP는 알려진 호스트
        assert engine.analyze(pkt) is None

    def test_metadata_contains_networks(self):
        pkt = make_ip("10.0.0.5", "10.0.1.99")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "monitored_networks" in alert.metadata
        assert "10.0.0.0/8" in alert.metadata["monitored_networks"]

    def test_shutdown_resets_learned_hosts(self):
        # 학습된 IP를 등록
        pkt1 = make_ip("10.0.5.5", "10.0.0.1")  # 10.0.5.5 학습
        self.engine.analyze(pkt1)
        assert "10.0.5.5" in self.engine._known_ips
        # shutdown 후 동적 학습 결과 사라짐
        self.engine.shutdown()
        assert "10.0.5.5" not in self.engine._known_ips
        # 정적 known_hosts는 유지
        assert "10.0.0.1" in self.engine._known_ips

    def test_mitre_attack_ids(self):
        assert "T1018" in DarkIPEngine.mitre_attack_ids

    def test_requires_span(self):
        assert DarkIPEngine.requires_span is True
