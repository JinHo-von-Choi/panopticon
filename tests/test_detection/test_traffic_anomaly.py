"""Tests for traffic anomaly detection engine (Adaptive EWMA + Seasonal + MAD)."""

from __future__ import annotations

from scapy.all import ARP, IP, TCP, Ether

import pytest
from netwatcher.detection.engines.traffic_anomaly import TrafficAnomalyEngine
from netwatcher.detection.models import Severity
from netwatcher.detection.stats import AdaptiveEWMA, MADDetector, SeasonalBuffer
from netwatcher.detection.whitelist import Whitelist


def _make_tcp_packet(
    src_mac: str = "aa:bb:cc:dd:ee:01",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "1.2.3.4",
    size: int = 100,
) -> Ether:
    payload_size = max(0, size - 54)  # Ether(14) + IP(20) + TCP(20)
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=12345, dport=80, flags="PA")
        / (b"\x00" * payload_size)
    )


def _make_arp_packet(src_mac: str, src_ip: str) -> Ether:
    return (
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=src_mac, psrc=src_ip)
    )


def _make_engine(cfg_overrides: dict | None = None) -> TrafficAnomalyEngine:
    """테스트용 엔진 인스턴스를 생성한다."""
    cfg = {
        "enabled": True,
        "ewma_span": 60,
        "z_threshold": 3.0,
        "mad_threshold": 3.5,
        "max_tracked_hosts": 5000,
    }
    if cfg_overrides:
        cfg.update(cfg_overrides)
    return TrafficAnomalyEngine(cfg)


def _make_engine_with_whitelist(
    engine_cfg: dict | None = None,
    wl_cfg: dict | None = None,
) -> TrafficAnomalyEngine:
    """whitelist가 주입된 엔진 인스턴스를 생성한다."""
    cfg = {
        "enabled": True,
        "ewma_span": 60,
        "z_threshold": 3.0,
        "mad_threshold": 3.5,
        "max_tracked_hosts": 5000,
    }
    if engine_cfg:
        cfg.update(engine_cfg)
    engine = TrafficAnomalyEngine(cfg)
    if wl_cfg is not None:
        wl = Whitelist(wl_cfg)
    else:
        wl = Whitelist({
            "ips": [], "ip_ranges": [], "macs": [],
            "domains": [], "domain_suffixes": [],
        })
    engine.set_whitelist(wl)
    return engine


# ---------------------------------------------------------------------------
# Stats 단위 테스트
# ---------------------------------------------------------------------------

class TestAdaptiveEWMA:
    def test_not_ready_initially(self):
        ewma = AdaptiveEWMA(span=10)
        assert not ewma.ready

    def test_ready_after_three_updates(self):
        ewma = AdaptiveEWMA(span=10)
        for v in [1.0, 2.0, 3.0]:
            ewma.update(v)
        assert ewma.ready

    def test_constant_input_zero_zscore(self):
        ewma = AdaptiveEWMA(span=10)
        for _ in range(20):
            z = ewma.update(5.0)
        assert abs(z) < 0.01

    def test_spike_produces_high_zscore(self):
        ewma = AdaptiveEWMA(span=10)
        # 약간의 변동이 있는 안정 데이터로 sigma를 구축
        for i in range(30):
            ewma.update(10.0 + (0.5 if i % 2 else -0.5))
        z = ewma.update(100.0)
        assert z > 3.0


class TestMADDetector:
    def test_not_enough_data(self):
        mad = MADDetector(window_size=50)
        assert mad.update(1.0) == 0.0
        assert mad.update(2.0) == 0.0

    def test_constant_zero_zscore(self):
        mad = MADDetector(window_size=50)
        for _ in range(20):
            z = mad.update(5.0)
        assert abs(z) == 0.0  # MAD = 0 이면 0.0 반환

    def test_spike_detected(self):
        mad = MADDetector(window_size=50)
        for _ in range(50):
            mad.update(10.0 + (0.5 if _ % 2 else -0.5))
        z = mad.update(100.0)
        assert abs(z) > 3.0


class TestSeasonalBuffer:
    def test_not_ready_initially(self):
        sb = SeasonalBuffer()
        assert not sb.ready

    def test_factor_before_ready(self):
        sb = SeasonalBuffer()
        sb.update(0, 10.0)
        assert sb.get_factor(0) == 1.0

    def test_ready_after_168_updates(self):
        sb = SeasonalBuffer()
        for i in range(168):
            sb.update(i % 168, 10.0)
        assert sb.ready

    def test_factor_uniform_is_one(self):
        sb = SeasonalBuffer()
        for i in range(168):
            sb.update(i, 10.0)
        factor = sb.get_factor(0)
        assert abs(factor - 1.0) < 0.01

    def test_factor_nonuniform(self):
        sb = SeasonalBuffer()
        for i in range(168):
            val = 20.0 if i == 0 else 10.0
            sb.update(i, val)
        factor_0 = sb.get_factor(0)
        factor_1 = sb.get_factor(1)
        assert factor_0 > factor_1


# ---------------------------------------------------------------------------
# 엔진 통합 테스트
# ---------------------------------------------------------------------------

class TestTrafficAnomalyEngine:
    def setup_method(self):
        self.engine = _make_engine_with_whitelist()

    def test_new_device_alert(self):
        """whitelist가 설정되어 있고, 미등록 MAC이면 New Device 알림을 발생시킨다."""
        pkt = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01", src_ip="192.168.1.10")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert alert.severity == Severity.INFO
        assert "New Device" in alert.title or "New" in alert.title
        assert alert.source_mac == "aa:bb:cc:dd:ee:01"

    def test_known_device_no_alert(self):
        """동일 MAC은 두 번째 이후 알림을 발생시키지 않는다."""
        pkt = _make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01")
        self.engine.analyze(pkt)
        alert = self.engine.analyze(_make_tcp_packet(src_mac="aa:bb:cc:dd:ee:01"))
        assert alert is None

    def test_broadcast_mac_ignored(self):
        pkt = (
            Ether(src="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.1.1", dst="1.2.3.4")
            / TCP()
        )
        alert = self.engine.analyze(pkt)
        assert alert is None

    def test_arp_device_detection(self):
        """ARP 패킷의 src MAC도 신규 장치로 탐지한다."""
        pkt = _make_arp_packet("aa:bb:cc:dd:ee:02", "192.168.1.20")
        alert = self.engine.analyze(pkt)
        assert alert is not None
        assert "New Device" in alert.title or "New" in alert.title


class TestNormalTrafficNoAlert:
    """일정한 트래픽은 이상 알림을 발생시키지 않는다."""

    def test_normal_traffic_no_alert(self):
        engine = _make_engine({"z_threshold": 3.0, "mad_threshold": 3.5})

        for tick in range(30):
            for _ in range(5):
                engine.analyze(_make_tcp_packet(src_ip="10.0.0.1"))
            alerts = engine.on_tick(0)
            anomaly_alerts = [a for a in alerts if "Volume" in a.title]
            assert len(anomaly_alerts) == 0, f"tick {tick}에서 오탐 발생"


class TestEwmaSpikeDetection:
    """갑작스러운 10배 트래픽 급증 시 알림을 발생시킨다."""

    def test_ewma_spike_detection(self):
        engine = _make_engine({
            "ewma_span": 10,
            "z_threshold": 2.5,
            "mad_threshold": 2.5,
        })

        # 안정적 베이스라인 구축 (20틱, 약간의 변동 포함하여 sigma > 0)
        for tick in range(20):
            count = 10 if tick % 2 == 0 else 12
            for _ in range(count):
                engine.analyze(_make_tcp_packet(src_ip="10.0.0.1"))
            engine.on_tick(0)

        # 10배 트래픽 급증
        for _ in range(110):
            engine.analyze(_make_tcp_packet(src_ip="10.0.0.1"))
        alerts = engine.on_tick(0)

        anomaly_alerts = [a for a in alerts if "Volume" in a.title]
        assert len(anomaly_alerts) >= 1
        assert anomaly_alerts[0].source_ip == "10.0.0.1"
        assert anomaly_alerts[0].metadata["ewma_z_score"] > 2.0 or \
               anomaly_alerts[0].metadata["mad_z_score"] > 2.0


class TestMADRobustness:
    """점진적 변동 후 급격한 스파이크를 MAD가 탐지한다."""

    def test_mad_robustness(self):
        engine = _make_engine({
            "ewma_span": 30,
            "z_threshold": 10.0,   # EWMA 임계값을 높여서 MAD만 트리거
            "mad_threshold": 3.0,
        })

        # 점진적으로 증가하는 트래픽 (drift)
        for i in range(30):
            count = 10 + i  # 10 -> 39 서서히 증가
            for _ in range(count):
                engine.analyze(_make_tcp_packet(src_ip="10.0.0.2"))
            engine.on_tick(0)

        # 급격한 스파이크: 현재 추세 대비 10배
        for _ in range(400):
            engine.analyze(_make_tcp_packet(src_ip="10.0.0.2"))
        alerts = engine.on_tick(0)

        anomaly_alerts = [a for a in alerts if "Volume" in a.title]
        assert len(anomaly_alerts) >= 1
        assert abs(anomaly_alerts[0].metadata["mad_z_score"]) > 2.0


class TestSeasonalCorrection:
    """SeasonalBuffer가 계절 보정 계수를 올바르게 산출하는지 검증한다."""

    def test_seasonal_correction(self):
        sb = SeasonalBuffer()

        # 168슬롯 채우기: 슬롯 0은 높은 값, 나머지는 낮은 값
        for i in range(168):
            val = 50.0 if i == 0 else 10.0
            sb.update(i, val)

        assert sb.ready

        # 슬롯 0의 계수는 1.0보다 커야 함 (트래픽이 평균보다 높은 시간대)
        factor_peak = sb.get_factor(0)
        factor_low  = sb.get_factor(1)

        assert factor_peak > 1.0
        assert factor_low < 1.0
        assert factor_peak > factor_low


class TestShutdownClears:
    """shutdown() 호출 시 모든 상태가 초기화된다."""

    def test_shutdown_clears(self):
        engine = _make_engine()

        for _ in range(10):
            engine.analyze(_make_tcp_packet(src_ip="10.0.0.1"))
        engine.on_tick(0)

        engine.shutdown()

        assert len(engine._tick_counters) == 0
        assert len(engine._host_stats) == 0
        assert len(engine._new_devices_alerted) == 0
        assert engine._current_packets == 0
        assert engine._current_bytes == 0
        assert not engine._seasonal.ready


class TestConfigSchema:
    """config_schema에 필수 키가 존재하는지 검증한다."""

    def test_config_schema(self):
        schema = TrafficAnomalyEngine.config_schema
        assert "ewma_span" in schema
        assert "z_threshold" in schema
        assert "mad_threshold" in schema
        assert "max_tracked_hosts" in schema

        for key, spec in schema.items():
            assert "type" in spec
            assert "default" in spec


class TestGlobalCounters:
    """글로벌 카운터 동작을 검증한다."""

    def test_bytes_tracked(self):
        engine = _make_engine()
        pkt = _make_tcp_packet(src_ip="192.168.1.10", size=500)
        engine.analyze(pkt)
        assert engine._current_bytes > 0

    def test_counters_reset_on_tick(self):
        engine = _make_engine()
        pkt = _make_tcp_packet(size=500)
        engine.analyze(pkt)
        assert engine._current_packets == 1

        engine.on_tick(0)
        assert engine._current_packets == 0
        assert engine._current_bytes == 0
