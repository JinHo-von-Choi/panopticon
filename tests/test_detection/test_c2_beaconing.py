"""C2 비콘 탐지 엔진 테스트."""

from __future__ import annotations

import time

import pytest
from scapy.all import ARP, IP, TCP, UDP, Ether, Packet

from netwatcher.detection.engines.c2_beaconing import C2BeaconingEngine, _cv, _is_internal
from netwatcher.detection.models import Severity


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------

def make_tcp(src: str, dst: str, dport: int) -> Packet:
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport)


def make_udp(src: str, dst: str, dport: int) -> Packet:
    return Ether() / IP(src=src, dst=dst) / UDP(dport=dport)


BASE_CONFIG = {
    "enabled": True,
    "cv_threshold": 0.3,
    "min_connections": 5,   # 테스트에서 빠르게 수렴하도록 낮춤
    "min_interval": 1.0,
    "max_interval": 3600.0,
    "cooldown_seconds": 3600,
}


def _feed_periodic(engine: C2BeaconingEngine, src: str, dst: str, dport: int,
                   interval: float, count: int) -> list:
    """일정 주기로 패킷을 전송하는 시뮬레이션. 마지막 분석 결과를 반환한다."""
    pkt = make_tcp(src, dst, dport)
    results = []
    # 세션 타임스탬프를 직접 조작하여 일정 IAT 주입
    key = (src, dst, dport)
    now = time.time()
    engine._sessions[key] = [now - interval * count]
    for i in range(count):
        engine._sessions[key][0] = now - interval * (count - i)
        iat = interval
        if len(engine._sessions[key]) > 1:
            engine._sessions[key].append(iat)
        else:
            engine._sessions[key].append(iat)

    # 마지막 패킷으로 평가
    engine._sessions[key][0] = now - interval
    alert = engine.analyze(pkt)
    return alert


# ---------------------------------------------------------------------------
# _cv 단위 테스트
# ---------------------------------------------------------------------------

class TestCV:
    def test_perfectly_periodic(self):
        # CV = 0 for identical intervals
        assert _cv([10.0, 10.0, 10.0, 10.0, 10.0]) == pytest.approx(0.0, abs=1e-9)

    def test_irregular(self):
        # 불규칙한 간격은 높은 CV
        assert _cv([1.0, 10.0, 100.0, 5.0, 3.0]) > 0.5

    def test_single_value_returns_one(self):
        assert _cv([5.0]) == 1.0

    def test_empty_returns_one(self):
        assert _cv([]) == 1.0

    def test_zero_mean_returns_one(self):
        assert _cv([0.0, 0.0, 0.0]) == 1.0


# ---------------------------------------------------------------------------
# _is_internal
# ---------------------------------------------------------------------------

class TestIsInternal:
    def test_rfc1918_10(self):
        assert _is_internal("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert _is_internal("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert _is_internal("192.168.1.1") is True

    def test_loopback(self):
        assert _is_internal("127.0.0.1") is True

    def test_public(self):
        assert _is_internal("8.8.8.8") is False


# ---------------------------------------------------------------------------
# C2BeaconingEngine 엔진 테스트
# ---------------------------------------------------------------------------

class TestC2BeaconingEngine:
    def setup_method(self):
        self.engine = C2BeaconingEngine(BASE_CONFIG)

    def test_non_ip_returns_none(self):
        pkt = Ether() / ARP()
        assert self.engine.analyze(pkt) is None

    def test_internal_dst_returns_none(self):
        pkt = make_tcp("10.0.0.5", "10.0.1.1", 80)
        assert self.engine.analyze(pkt) is None

    def test_no_tcpudp_returns_none(self):
        from scapy.all import ICMP
        pkt = Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / ICMP()
        assert self.engine.analyze(pkt) is None

    def test_first_packet_returns_none(self):
        pkt = make_tcp("10.0.0.5", "1.2.3.4", 443)
        assert self.engine.analyze(pkt) is None

    def test_insufficient_samples_returns_none(self):
        pkt = make_tcp("10.0.0.5", "1.2.3.4", 443)
        for _ in range(3):
            result = self.engine.analyze(pkt)
        assert result is None

    def test_periodic_beacon_detected(self):
        """완전히 주기적인 패킷은 비콘으로 탐지되어야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        # min_connections=5개의 IAT를 직접 주입 (완벽한 주기 60초)
        self.engine._sessions[key] = [time.time() - 60, 60.0, 60.0, 60.0, 60.0, 60.0]
        pkt = make_tcp(src, dst, dport)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.WARNING
        assert alert.engine == "c2_beaconing"
        assert alert.source_ip == src
        assert alert.dest_ip == dst
        assert alert.metadata["cv"] < 0.3

    def test_irregular_traffic_no_alert(self):
        """불규칙한 트래픽은 알림을 발생시키지 않아야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 80
        key = (src, dst, dport)
        # 매우 불규칙한 IAT (사람이 발생시키는 트래픽)
        self.engine._sessions[key] = [time.time() - 5,
                                       1.0, 120.0, 5.0, 300.0, 2.0]
        pkt = make_tcp(src, dst, dport)
        assert self.engine.analyze(pkt) is None

    def test_avg_iat_too_short_no_alert(self):
        """평균 IAT가 min_interval 이하면 비콘으로 보지 않는다."""
        engine = C2BeaconingEngine({**BASE_CONFIG, "min_interval": 10.0})
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        # 평균 IAT ≈ 0.5초 (너무 빠름)
        engine._sessions[key] = [time.time() - 0.5,
                                  0.5, 0.5, 0.5, 0.5, 0.5]
        pkt = make_tcp(src, dst, dport)
        assert engine.analyze(pkt) is None

    def test_avg_iat_too_long_no_alert(self):
        """평균 IAT가 max_interval 초과면 알림 없음."""
        engine = C2BeaconingEngine({**BASE_CONFIG, "max_interval": 100.0})
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        # 평균 IAT ≈ 7200초 (너무 느림)
        engine._sessions[key] = [time.time() - 7200,
                                  7200.0, 7200.0, 7200.0, 7200.0, 7200.0]
        pkt = make_tcp(src, dst, dport)
        assert engine.analyze(pkt) is None

    def test_cooldown_suppresses_duplicate(self):
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        self.engine._sessions[key] = [time.time() - 60,
                                       60.0, 60.0, 60.0, 60.0, 60.0]
        pkt = make_tcp(src, dst, dport)
        alert1 = self.engine.analyze(pkt)
        assert alert1 is not None
        # 즉시 재분석 — 쿨다운 내
        self.engine._sessions[key] = [time.time() - 60,
                                       60.0, 60.0, 60.0, 60.0, 60.0]
        alert2 = self.engine.analyze(pkt)
        assert alert2 is None

    def test_udp_beacon_detected(self):
        """UDP 비콘도 탐지되어야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 53
        key = (src, dst, dport)
        self.engine._sessions[key] = [time.time() - 30,
                                       30.0, 30.0, 30.0, 30.0, 30.0]
        pkt = make_udp(src, dst, dport)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.metadata["dst_port"] == 53

    def test_metadata_fields(self):
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        self.engine._sessions[key] = [time.time() - 60,
                                       60.0, 60.0, 60.0, 60.0, 60.0]
        pkt = make_tcp(src, dst, dport)
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "avg_iat_seconds" in alert.metadata
        assert "cv" in alert.metadata
        assert "sample_count" in alert.metadata
        assert "dst_port" in alert.metadata

    def test_shutdown_clears_state(self):
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        self.engine._sessions[key] = [time.time(), 60.0]
        self.engine._alerted[key] = time.time()
        self.engine.shutdown()
        assert len(self.engine._sessions) == 0
        assert len(self.engine._alerted) == 0

    def test_mitre_attack_ids(self):
        assert "T1071" in C2BeaconingEngine.mitre_attack_ids
        assert "T1571" in C2BeaconingEngine.mitre_attack_ids

    def test_different_ports_tracked_separately(self):
        """동일 dst_ip라도 포트가 다르면 별도 세션으로 추적한다."""
        src, dst = "10.0.0.5", "1.2.3.4"
        key80 = (src, dst, 80)
        key443 = (src, dst, 443)
        self.engine._sessions[key80] = [time.time() - 60,
                                         60.0, 60.0, 60.0, 60.0, 60.0]
        self.engine._sessions[key443] = [time.time() - 60,
                                          60.0, 60.0, 60.0, 60.0, 60.0]
        alert80 = self.engine.analyze(make_tcp(src, dst, 80))
        alert443 = self.engine.analyze(make_tcp(src, dst, 443))
        assert alert80 is not None
        assert alert443 is not None
        assert alert80.metadata["dst_port"] == 80
        assert alert443.metadata["dst_port"] == 443
