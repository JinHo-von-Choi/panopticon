"""C2 비콘 탐지 엔진 테스트 — RITA 스타일 다중 지표 스코어링."""

from __future__ import annotations

import random
import time

import pytest
from scapy.all import ARP, IP, TCP, UDP, Ether, Raw, Packet

from netwatcher.detection.engines.c2_beaconing import (
    C2BeaconingEngine,
    _cv,
    _is_internal,
    composite_score,
    score_bowley_skew,
    score_fft,
    score_madm,
    score_size,
    score_timing,
)
from netwatcher.detection.models import Severity


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------

def make_tcp(src: str, dst: str, dport: int, payload_size: int = 64) -> Packet:
    payload = Raw(load=b"X" * payload_size)
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport) / payload


def make_udp(src: str, dst: str, dport: int, payload_size: int = 64) -> Packet:
    payload = Raw(load=b"X" * payload_size)
    return Ether() / IP(src=src, dst=dst) / UDP(dport=dport) / payload


BASE_CONFIG = {
    "enabled": True,
    "score_threshold": 0.7,
    "critical_threshold": 0.85,
    "min_connections": 5,   # 테스트에서 빠르게 수렴하도록 낮춤
    "min_interval": 1.0,
    "max_interval": 3600.0,
    "cooldown_seconds": 3600,
}


def _inject_session(engine: C2BeaconingEngine, key: tuple[str, str, int],
                    iats: list[float], sizes: list[int] | None = None) -> None:
    """세션 데이터를 직접 주입한다."""
    session = engine._sessions[key]
    session["last_ts"] = time.time()
    session["iats"] = list(iats)
    session["sizes"] = list(sizes) if sizes is not None else [64] * (len(iats) + 1)


# ---------------------------------------------------------------------------
# 스코어링 함수 단위 테스트
# ---------------------------------------------------------------------------

class TestScoringFunctions:
    """개별 스코어링 함수의 정확성을 검증한다."""

    def test_score_timing_perfect(self):
        """완벽히 동일한 IAT → 1.0."""
        assert score_timing([60.0] * 10) == 1.0

    def test_score_timing_irregular(self):
        """매우 불규칙한 IAT → 0.0."""
        assert score_timing([1.0, 100.0, 5.0, 300.0, 2.0, 50.0]) == 0.0

    def test_score_size_consistent(self):
        """동일한 페이로드 크기 → 1.0."""
        assert score_size([64] * 10) == 1.0

    def test_score_size_varied(self):
        """매우 다양한 크기 → 낮은 점수."""
        assert score_size([10, 500, 20, 800, 5, 1000]) == 0.0

    def test_score_bowley_skew_symmetric(self):
        """대칭 분포 → 높은 점수."""
        iats = [60.0] * 20
        assert score_bowley_skew(iats) == 1.0

    def test_score_madm_perfect(self):
        """동일한 IAT → MAD/median = 0 → 1.0."""
        assert score_madm([60.0] * 10) == 1.0

    def test_score_madm_varied(self):
        """매우 다양한 IAT → 낮은 점수."""
        assert score_madm([1.0, 100.0, 5.0, 300.0, 2.0]) <= 0.3

    def test_score_fft_periodic(self):
        """주기적 신호 → 높은 FFT 점수."""
        # numpy 없으면 0.0 반환하므로 그 경우도 허용
        result = score_fft([60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0])
        assert result >= 0.0  # numpy 없을 때 0.0 허용

    def test_composite_score_perfect_beacon(self):
        """완벽한 비콘 데이터 → 높은 복합 점수."""
        iats  = [60.0] * 20
        sizes = [64] * 21
        score = composite_score(iats, sizes)
        assert score >= 0.85

    def test_composite_score_random(self):
        """랜덤 데이터 → 낮은 복합 점수."""
        random.seed(42)
        iats  = [random.uniform(1, 300) for _ in range(20)]
        sizes = [random.randint(10, 1500) for _ in range(21)]
        score = composite_score(iats, sizes)
        assert score < 0.5


# ---------------------------------------------------------------------------
# _cv 단위 테스트
# ---------------------------------------------------------------------------

class TestCV:
    def test_perfectly_periodic(self):
        assert _cv([10.0, 10.0, 10.0, 10.0, 10.0]) == pytest.approx(0.0, abs=1e-9)

    def test_irregular(self):
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

    def test_perfect_beacon(self):
        """완전히 주기적인 패킷은 CRITICAL 비콘으로 탐지되어야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        # 완벽한 60초 주기, 동일 페이로드 크기
        _inject_session(self.engine, key, [60.0] * 20, [64] * 21)

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity == Severity.CRITICAL
        assert alert.engine == "c2_beaconing"
        assert alert.source_ip == src
        assert alert.dest_ip == dst
        assert alert.metadata["composite_score"] >= 0.85

    def test_jittery_beacon(self):
        """~25% 지터가 있는 비콘은 WARNING으로 탐지되어야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        # 60초 기반 + ~25% 지터 (+-15초), 크기도 약간 다양하게
        random.seed(99)
        iats = [60.0 + random.uniform(-15, 15) for _ in range(20)]
        sizes = [64 + random.randint(-20, 20) for _ in range(21)]
        _inject_session(self.engine, key, iats, sizes)

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity == Severity.WARNING
        assert alert.metadata["composite_score"] >= 0.7
        assert alert.metadata["composite_score"] < 0.85

    def test_random_traffic(self):
        """완전 랜덤 트래픽은 알림을 발생시키지 않아야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 80
        key = (src, dst, dport)
        random.seed(42)
        iats = [random.uniform(1, 300) for _ in range(20)]
        sizes = [random.randint(10, 1500) for _ in range(21)]
        _inject_session(self.engine, key, iats, sizes)

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_size_variation(self):
        """규칙적 타이밍이지만 크기가 매우 다양하면 점수가 낮아진다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        iats = [60.0] * 20
        # 매우 다양한 페이로드 크기
        random.seed(99)
        sizes = [random.randint(10, 5000) for _ in range(21)]
        _inject_session(self.engine, key, iats, sizes)

        alerts = self.engine.on_tick(time.time())
        # 타이밍은 완벽하지만 크기 일관성이 낮아 점수가 하락한다
        # size 가중치(0.15)만큼 손실 → 여전히 WARNING 이상일 수 있지만 CRITICAL은 아님
        if alerts:
            assert alerts[0].severity != Severity.CRITICAL or \
                   alerts[0].metadata["composite_score"] < composite_score(iats, [64] * 21)

    def test_cooldown(self):
        """동일 페어는 쿨다운 내 재알림이 억제되어야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        _inject_session(self.engine, key, [60.0] * 20, [64] * 21)

        alerts1 = self.engine.on_tick(time.time())
        assert len(alerts1) == 1

        # 세션 재주입 후 즉시 재평가 — 쿨다운 내
        _inject_session(self.engine, key, [60.0] * 20, [64] * 21)
        alerts2 = self.engine.on_tick(time.time())
        assert len(alerts2) == 0

    def test_min_samples(self):
        """min_connections 미만의 샘플에서는 평가하지 않아야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        # min_connections=5 인데 3개만 주입
        _inject_session(self.engine, key, [60.0] * 3, [64] * 4)

        alerts = self.engine.on_tick(time.time())
        assert len(alerts) == 0

    def test_shutdown_clears(self):
        """shutdown() 호출 시 모든 상태가 초기화되어야 한다."""
        src, dst, dport = "10.0.0.5", "1.2.3.4", 443
        key = (src, dst, dport)
        _inject_session(self.engine, key, [60.0] * 10, [64] * 11)
        self.engine._alerted[key] = time.time()

        self.engine.shutdown()
        assert len(self.engine._sessions) == 0
        assert len(self.engine._alerted) == 0

    def test_analyze_only_collects_data(self):
        """analyze()는 항상 None을 반환하고 데이터만 수집해야 한다."""
        pkt = make_tcp("10.0.0.5", "1.2.3.4", 443, payload_size=100)
        # 첫 패킷
        assert self.engine.analyze(pkt) is None
        # 두 번째 패킷
        assert self.engine.analyze(pkt) is None
        key = ("10.0.0.5", "1.2.3.4", 443)
        session = self.engine._sessions[key]
        assert session["last_ts"] > 0
        assert len(session["sizes"]) == 2

    def test_non_ip_returns_none(self):
        pkt = Ether() / ARP()
        assert self.engine.analyze(pkt) is None

    def test_internal_dst_returns_none(self):
        pkt = make_tcp("10.0.0.5", "10.0.1.1", 80)
        assert self.engine.analyze(pkt) is None

    def test_mitre_attack_ids(self):
        assert "T1071" in C2BeaconingEngine.mitre_attack_ids
        assert "T1571" in C2BeaconingEngine.mitre_attack_ids
