"""세그먼트 격리 위반 탐지 엔진 테스트."""

from __future__ import annotations

import time

import pytest
from scapy.all import IP, TCP, UDP, Ether, Packet

from netwatcher.detection.engines.segment_violation import SegmentViolationEngine
from netwatcher.detection.models import Severity
from netwatcher.detection.segmentation import is_allowed, parse_flows


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------

def make_tcp(src: str, dst: str, dport: int) -> Packet:
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport)


def make_udp(src: str, dst: str, dport: int) -> Packet:
    return Ether() / IP(src=src, dst=dst) / UDP(dport=dport)


BASE_CONFIG = {
    "enabled": True,
    "cooldown_seconds": 300,
    "allowed_flows": [
        {
            "src_net": "10.0.0.0/24",
            "dst_net": "10.0.1.0/24",
            "ports": [80, 443],
            "proto": "tcp",
        },
        {
            "src_net": "10.0.2.0/24",
            "dst_net": "0.0.0.0/0",
            "ports": [],
            "proto": "any",
        },
    ],
}


# ---------------------------------------------------------------------------
# parse_flows / is_allowed 단위 테스트
# ---------------------------------------------------------------------------

class TestParseFlows:
    def test_parses_valid_entry(self):
        flows = parse_flows([{"src_net": "10.0.0.0/24", "dst_net": "10.0.1.0/24", "ports": [80], "proto": "tcp"}])
        assert len(flows) == 1
        assert flows[0].proto == "tcp"
        assert 80 in flows[0].ports

    def test_skips_invalid_entry(self):
        flows = parse_flows([{"src_net": "bad", "dst_net": "10.0.1.0/24"}])
        assert len(flows) == 0

    def test_empty_ports_means_all(self):
        flows = parse_flows([{"src_net": "10.0.0.0/8", "dst_net": "0.0.0.0/0", "ports": [], "proto": "any"}])
        assert len(flows[0].ports) == 0


class TestIsAllowed:
    def setup_method(self):
        self.flows = parse_flows(BASE_CONFIG["allowed_flows"])

    def test_allowed_flow(self):
        assert is_allowed(self.flows, "10.0.0.5", "10.0.1.10", 80, "tcp") is True

    def test_disallowed_dst_net(self):
        # dst가 허용 dst_net 밖
        assert is_allowed(self.flows, "10.0.0.5", "10.0.2.10", 80, "tcp") is False

    def test_disallowed_port(self):
        # 포트 22는 허용 목록에 없음
        assert is_allowed(self.flows, "10.0.0.5", "10.0.1.10", 22, "tcp") is False

    def test_any_dst_flow(self):
        # 10.0.2.x는 모든 목적지 허용
        assert is_allowed(self.flows, "10.0.2.1", "8.8.8.8", 53, "udp") is True

    def test_empty_flows_always_allowed(self):
        assert is_allowed([], "1.2.3.4", "5.6.7.8", 22, "tcp") is True

    def test_invalid_ip_allowed(self):
        assert is_allowed(self.flows, "not_an_ip", "10.0.1.1", 80, "tcp") is True


# ---------------------------------------------------------------------------
# SegmentViolationEngine 엔진 테스트
# ---------------------------------------------------------------------------

class TestSegmentViolationEngine:
    def setup_method(self):
        self.engine = SegmentViolationEngine(BASE_CONFIG)

    def test_allowed_flow_returns_none(self):
        pkt = make_tcp("10.0.0.5", "10.0.1.10", 80)
        assert self.engine.analyze(pkt) is None

    def test_violation_returns_alert(self):
        pkt = make_tcp("10.0.0.5", "10.0.3.1", 22)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert alert.engine == "segment_violation"
        assert alert.source_ip == "10.0.0.5"
        assert alert.dest_ip == "10.0.3.1"
        assert alert.mitre_attack_id is None  # 레지스트리 없이 호출 시 None

    def test_violation_metadata(self):
        pkt = make_tcp("10.0.0.5", "10.0.3.1", 22)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.metadata["proto"] == "tcp"
        assert alert.metadata["dst_port"] == 22

    def test_udp_violation(self):
        pkt = make_udp("10.0.0.5", "10.0.3.1", 53)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.metadata["proto"] == "udp"

    def test_cooldown_suppresses_duplicate(self):
        pkt = make_tcp("10.0.0.5", "10.0.3.1", 22)
        alert1 = self.engine.analyze(pkt)
        assert alert1 is not None
        # 즉시 재호출 — 쿨다운 내
        alert2 = self.engine.analyze(pkt)
        assert alert2 is None

    def test_cooldown_zero_allows_repeat(self):
        engine = SegmentViolationEngine({**BASE_CONFIG, "cooldown_seconds": 0})
        pkt = make_tcp("10.0.0.5", "10.0.3.1", 22)
        assert engine.analyze(pkt) is not None
        assert engine.analyze(pkt) is not None

    def test_no_flows_always_none(self):
        engine = SegmentViolationEngine({"enabled": True, "allowed_flows": []})
        pkt = make_tcp("10.0.0.1", "192.168.1.1", 22)
        assert engine.analyze(pkt) is None

    def test_non_ip_packet_returns_none(self):
        from scapy.all import ARP
        pkt = Ether() / ARP()
        assert self.engine.analyze(pkt) is None

    def test_mitre_attack_ids(self):
        assert "T1599" in SegmentViolationEngine.mitre_attack_ids

    def test_requires_span(self):
        assert SegmentViolationEngine.requires_span is True
