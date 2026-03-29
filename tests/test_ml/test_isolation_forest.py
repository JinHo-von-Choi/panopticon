"""IsolationForestEngine 단위 테스트.

sklearn을 mock하여 의존성 없이 엔진 동작을 검증한다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import sys
import time
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

np = pytest.importorskip("numpy")
from scapy.all import IP, TCP, UDP, Ether

from netwatcher.detection.models import Alert, Severity


def _make_mock_sklearn():
    """sklearn.ensemble.IsolationForest를 mock하는 모듈을 생성한다."""
    mock_model = MagicMock()
    # decision_function: 양수 = 정상, 음수 = 이상
    mock_model.decision_function.return_value = np.array([0.1])
    mock_model.fit.return_value = mock_model

    mock_ensemble = MagicMock()
    mock_ensemble.IsolationForest.return_value = mock_model

    mock_sklearn = MagicMock()
    mock_sklearn.ensemble = mock_ensemble

    return mock_sklearn, mock_ensemble, mock_model


@pytest.fixture
def mock_sklearn():
    """sklearn을 mock하고 엔진 모듈을 재로드한다."""
    mock_sklearn_mod, mock_ensemble, mock_model = _make_mock_sklearn()

    with patch.dict(sys.modules, {
        "sklearn": mock_sklearn_mod,
        "sklearn.ensemble": mock_ensemble,
    }):
        # 모듈 재로드하여 mock이 적용되도록
        import netwatcher.ml.isolation_forest_engine as engine_mod
        engine_mod._SKLEARN_AVAILABLE = True
        engine_mod._IsolationForest = mock_ensemble.IsolationForest
        yield engine_mod, mock_model


@pytest.fixture
def engine_config():
    """테스트용 엔진 설정."""
    return {
        "enabled": True,
        "baseline_hours": 0,  # 즉시 학습
        "anomaly_threshold": 0.5,
        "retrain_interval_hours": 168,
        "contamination": 0.01,
        "n_estimators": 50,
    }


def _make_tcp_packet(src_ip: str, dst_ip: str, dport: int = 80, size: int = 100):
    """테스트용 TCP 패킷을 생성한다."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=dport)
    # 패킷 크기를 지정하기 위해 패딩
    raw = bytes(pkt)
    if len(raw) < size:
        raw += b"\x00" * (size - len(raw))
    return Ether(raw)


def _make_udp_packet(src_ip: str, dst_ip: str, dport: int = 53, size: int = 80):
    """테스트용 UDP 패킷을 생성한다."""
    pkt = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(dport=dport)
    raw = bytes(pkt)
    if len(raw) < size:
        raw += b"\x00" * (size - len(raw))
    return Ether(raw)


class TestIsolationForestEngineInit:
    """엔진 초기화 검증."""

    def test_engine_name(self, mock_sklearn, engine_config):
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        assert eng.name == "ml_anomaly"

    def test_engine_type_is_cpu(self, mock_sklearn, engine_config):
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        assert eng.engine_type == "cpu"

    def test_enabled_when_sklearn_available(self, mock_sklearn, engine_config):
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        assert eng.enabled is True

    def test_disabled_when_sklearn_unavailable(self, engine_config):
        """sklearn이 없으면 자동 비활성화된다."""
        import netwatcher.ml.isolation_forest_engine as engine_mod
        original = engine_mod._SKLEARN_AVAILABLE
        engine_mod._SKLEARN_AVAILABLE = False
        try:
            eng = engine_mod.IsolationForestEngine(engine_config)
            assert eng.enabled is False
        finally:
            engine_mod._SKLEARN_AVAILABLE = original


class TestIsolationForestAnalyze:
    """패킷 분석(analyze) 검증."""

    def test_analyze_returns_none(self, mock_sklearn, engine_config):
        """analyze()는 항상 None을 반환한다 (on_tick에서 알림 생성)."""
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        pkt = _make_tcp_packet("10.0.0.1", "10.0.0.2", dport=80)
        assert eng.analyze(pkt) is None

    def test_analyze_feeds_feature_extractor(self, mock_sklearn, engine_config):
        """analyze()가 feature_extractor에 데이터를 전달한다."""
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2", dport=80))
        features = eng._feature_extractor.extract("10.0.0.1")
        assert features is not None

    def test_analyze_ignores_non_ip_packets(self, mock_sklearn, engine_config):
        """IP 레이어가 없는 패킷은 무시한다."""
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        pkt = Ether()
        assert eng.analyze(pkt) is None


class TestIsolationForestOnTick:
    """on_tick 동작 검증."""

    def test_on_tick_empty_during_baseline(self, mock_sklearn, engine_config):
        """베이스라인 수집 중에는 빈 리스트를 반환한다."""
        engine_mod, _ = mock_sklearn
        config = {**engine_config, "baseline_hours": 24}
        eng = engine_mod.IsolationForestEngine(config)
        eng._baseline_complete = False

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        alerts = eng.on_tick(time.time())
        assert alerts == []

    def test_on_tick_collects_samples_during_baseline(self, mock_sklearn, engine_config):
        """베이스라인 중 on_tick이 샘플을 수집한다."""
        engine_mod, _ = mock_sklearn
        config = {**engine_config, "baseline_hours": 24}
        eng = engine_mod.IsolationForestEngine(config)
        eng._baseline_complete = False

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        eng.on_tick(time.time())
        assert len(eng._baseline_samples) > 0

    def test_on_tick_fits_model_after_baseline(self, mock_sklearn, engine_config):
        """baseline_hours 경과 후 모델을 학습한다."""
        engine_mod, mock_model = mock_sklearn
        config = {**engine_config, "baseline_hours": 0}
        eng = engine_mod.IsolationForestEngine(config)
        eng._baseline_complete = False
        eng._start_time = time.time() - 3600  # 1시간 전

        for _ in range(15):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        eng.on_tick(time.time())
        assert eng._baseline_complete is True

    def test_on_tick_generates_alert_for_anomaly(self, mock_sklearn, engine_config):
        """모델이 이상을 탐지하면 알림을 생성한다."""
        engine_mod, mock_model = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        eng._baseline_complete = True
        # decision_function이 음수 반환 -> 이상 점수 높음
        mock_model.decision_function.return_value = np.array([-0.3])
        eng._model = mock_model

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2", dport=80))
        alerts = eng.on_tick(time.time())
        assert len(alerts) >= 1
        assert alerts[0].engine == "ml_anomaly"
        assert alerts[0].source_ip == "10.0.0.1"

    def test_on_tick_no_alert_for_normal(self, mock_sklearn, engine_config):
        """정상 점수에는 알림을 생성하지 않는다."""
        engine_mod, mock_model = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        eng._baseline_complete = True
        # decision_function이 양수 반환 -> 정상
        mock_model.decision_function.return_value = np.array([0.3])
        eng._model = mock_model

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2", dport=80))
        alerts = eng.on_tick(time.time())
        assert len(alerts) == 0

    def test_on_tick_resets_feature_extractor(self, mock_sklearn, engine_config):
        """on_tick 이후 feature_extractor가 리셋된다."""
        engine_mod, mock_model = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        eng._baseline_complete = True
        mock_model.decision_function.return_value = np.array([0.2])
        eng._model = mock_model

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        eng.on_tick(time.time())
        assert eng._feature_extractor.extract_all() == {}

    def test_on_tick_empty_without_packets(self, mock_sklearn, engine_config):
        """패킷이 없으면 빈 리스트를 반환한다."""
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        eng._baseline_complete = True
        alerts = eng.on_tick(time.time())
        assert alerts == []


class TestIsolationForestFeedback:
    """피드백 기반 임계값 조정 검증."""

    def test_report_fp_raises_threshold(self, mock_sklearn, engine_config):
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        initial = eng._threshold.current
        eng.report_feedback(is_false_positive=True)
        assert eng._threshold.current > initial

    def test_report_tp_lowers_threshold(self, mock_sklearn, engine_config):
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        initial = eng._threshold.current
        eng.report_feedback(is_false_positive=False)
        assert eng._threshold.current < initial


class TestIsolationForestAlertSeverity:
    """알림 심각도 분류 검증."""

    def test_critical_for_high_anomaly_score(self, mock_sklearn, engine_config):
        """이상 점수가 0.9 초과면 CRITICAL."""
        engine_mod, mock_model = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        eng._baseline_complete = True
        # decision_function -0.5 -> anomaly_score = 0.5 - (-0.5) = 1.0 (clamped)
        mock_model.decision_function.return_value = np.array([-0.5])
        eng._model = mock_model

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        alerts = eng.on_tick(time.time())
        assert len(alerts) >= 1
        assert alerts[0].severity == Severity.CRITICAL

    def test_warning_for_moderate_anomaly_score(self, mock_sklearn, engine_config):
        """이상 점수가 임계값 이상이지만 0.9 이하면 WARNING."""
        engine_mod, mock_model = mock_sklearn
        config = {**engine_config, "anomaly_threshold": 0.3}
        eng = engine_mod.IsolationForestEngine(config)
        eng._baseline_complete = True
        # decision_function -0.1 -> anomaly_score = 0.5 - (-0.1) = 0.6
        mock_model.decision_function.return_value = np.array([-0.1])
        eng._model = mock_model

        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        alerts = eng.on_tick(time.time())
        assert len(alerts) >= 1
        assert alerts[0].severity == Severity.WARNING


class TestIsolationForestShutdown:
    """엔진 종료 검증."""

    def test_shutdown_clears_state(self, mock_sklearn, engine_config):
        engine_mod, _ = mock_sklearn
        eng = engine_mod.IsolationForestEngine(engine_config)
        for _ in range(5):
            eng.analyze(_make_tcp_packet("10.0.0.1", "10.0.0.2"))
        eng._baseline_samples.append([1.0] * 10)
        eng.shutdown()
        assert eng._baseline_samples == []
        assert eng._feature_extractor.extract_all() == {}
