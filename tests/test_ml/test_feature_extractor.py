"""FeatureExtractor 단위 테스트.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import time

import pytest

from netwatcher.ml.feature_extractor import FeatureExtractor, _shannon_entropy


class TestShannonEntropy:
    """_shannon_entropy 헬퍼 함수 검증."""

    def test_empty_list(self):
        assert _shannon_entropy([]) == 0.0

    def test_single_value(self):
        assert _shannon_entropy([42]) == 0.0

    def test_uniform_distribution(self):
        # 4가지 동일 빈도 -> log2(4) = 2.0
        values = [1, 2, 3, 4]
        assert abs(_shannon_entropy(values) - 2.0) < 1e-9

    def test_skewed_distribution(self):
        # 하나의 값이 지배적이면 엔트로피가 낮다
        values = [1] * 100 + [2]
        assert _shannon_entropy(values) < 0.2


class TestFeatureExtractor:
    """FeatureExtractor 핵심 기능 검증."""

    def test_extract_returns_none_for_unknown_host(self):
        """추적되지 않은 호스트에 대해 None을 반환한다."""
        ext = FeatureExtractor(window_seconds=60)
        assert ext.extract("10.0.0.1") is None

    def test_extract_returns_none_for_single_packet(self):
        """패킷이 1개뿐이면 None을 반환한다 (최소 2개 필요)."""
        ext = FeatureExtractor(window_seconds=60)
        ext.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, 80)
        assert ext.extract("10.0.0.1") is None

    def test_extract_returns_feature_vector(self):
        """충분한 패킷이 있으면 10차원 벡터를 반환한다."""
        ext = FeatureExtractor(window_seconds=60)
        for i in range(5):
            ext.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 64 + i, 80 + i)
        features = ext.extract("10.0.0.1")
        assert features is not None
        assert len(features) == len(FeatureExtractor.FEATURE_NAMES)

    def test_feature_vector_values_are_finite(self):
        """모든 특징값이 유한수여야 한다."""
        ext = FeatureExtractor(window_seconds=60)
        for _ in range(10):
            ext.feed_packet("192.168.1.1", "8.8.8.8", "udp", 128, 53)
        features = ext.extract("192.168.1.1")
        assert features is not None
        for val in features:
            assert isinstance(val, float)
            assert val == val  # NaN 검사

    def test_protocol_ratios_sum_to_one(self):
        """TCP + UDP 비율이 1.0 이하여야 한다."""
        ext = FeatureExtractor(window_seconds=60)
        for _ in range(3):
            ext.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, 80)
        for _ in range(2):
            ext.feed_packet("10.0.0.1", "10.0.0.2", "udp", 100, 53)
        features = ext.extract("10.0.0.1")
        assert features is not None
        tcp_ratio = features[4]
        udp_ratio = features[5]
        assert 0.0 <= tcp_ratio <= 1.0
        assert 0.0 <= udp_ratio <= 1.0
        assert tcp_ratio + udp_ratio <= 1.0 + 1e-9

    def test_extract_all(self):
        """여러 호스트의 벡터를 일괄 추출한다."""
        ext = FeatureExtractor(window_seconds=60)
        for _ in range(3):
            ext.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, 80)
            ext.feed_packet("10.0.0.3", "10.0.0.4", "udp", 200, 443)
        result = ext.extract_all()
        assert "10.0.0.1" in result
        assert "10.0.0.3" in result
        assert len(result["10.0.0.1"]) == 10

    def test_reset_clears_state(self):
        """reset() 이후 모든 호스트 데이터가 초기화된다."""
        ext = FeatureExtractor(window_seconds=60)
        for _ in range(5):
            ext.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, 80)
        ext.reset()
        assert ext.extract("10.0.0.1") is None
        assert ext.extract_all() == {}

    def test_unique_ports_counted_correctly(self):
        """고유 포트 수가 정확히 카운트된다."""
        ext = FeatureExtractor(window_seconds=60)
        ports = [80, 443, 8080, 80, 443]  # 3 unique
        for port in ports:
            ext.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, port)
        features = ext.extract("10.0.0.1")
        assert features is not None
        unique_ports = features[2]
        assert unique_ports == 3.0

    def test_port_entropy_increases_with_diversity(self):
        """포트 다양성이 높을수록 엔트로피가 커진다."""
        # 단일 포트
        ext_single = FeatureExtractor(window_seconds=60)
        for _ in range(10):
            ext_single.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, 80)
        f_single = ext_single.extract("10.0.0.1")

        # 다양한 포트
        ext_diverse = FeatureExtractor(window_seconds=60)
        for i in range(10):
            ext_diverse.feed_packet("10.0.0.1", "10.0.0.2", "tcp", 100, 80 + i)
        f_diverse = ext_diverse.extract("10.0.0.1")

        assert f_single is not None and f_diverse is not None
        assert f_diverse[3] > f_single[3]  # port_entropy
