"""UnauthorizedDetector 테스트: 정책 로드, 위반 탐지."""

from __future__ import annotations

import pytest

from netwatcher.inventory.unauthorized_detector import UnauthorizedDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _policy(**kw) -> dict:
    """기본 정책 dict를 생성한다."""
    base = {
        "enabled":             True,
        "authorized_macs":     ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
        "authorized_ips":      ["192.168.1.100", "192.168.1.101"],
        "authorized_subnets":  ["10.0.0.0/24"],
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# 정책 로드
# ---------------------------------------------------------------------------

class TestLoadPolicy:
    def test_load_enables_detector(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        assert d.enabled is True

    def test_disabled_by_default(self):
        d = UnauthorizedDetector()
        assert d.enabled is False

    def test_load_disabled_policy(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy(enabled=False))
        assert d.enabled is False

    def test_mac_normalization(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy(authorized_macs=["AA:BB:CC:DD:EE:01"]))
        # 내부적으로 소문자로 저장
        result = d.check("aa:bb:cc:dd:ee:01", "192.168.1.100")
        assert result is None  # 인가됨

    def test_invalid_subnet_ignored(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy(authorized_subnets=["NOT_A_SUBNET", "10.0.0.0/24"]))
        # 유효한 서브넷만 로드, 에러 없음


# ---------------------------------------------------------------------------
# 비활성화 상태
# ---------------------------------------------------------------------------

class TestDisabled:
    def test_disabled_always_returns_none(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy(enabled=False))
        result = d.check("ff:ff:ff:ff:ff:ff", "1.2.3.4")
        assert result is None


# ---------------------------------------------------------------------------
# MAC 기반 탐지
# ---------------------------------------------------------------------------

class TestMACCheck:
    def test_authorized_mac_passes(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("aa:bb:cc:dd:ee:01", "192.168.1.100")
        assert result is None

    def test_unauthorized_mac_detected(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("ff:ff:ff:ff:ff:ff", "192.168.1.100")
        assert result is not None
        assert "MAC" in result["reason"]


# ---------------------------------------------------------------------------
# IP 기반 탐지
# ---------------------------------------------------------------------------

class TestIPCheck:
    def test_authorized_ip_passes(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("aa:bb:cc:dd:ee:01", "192.168.1.100")
        assert result is None

    def test_unauthorized_ip_detected(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("aa:bb:cc:dd:ee:01", "172.16.0.99")
        assert result is not None
        assert "IP" in result["reason"]

    def test_ip_in_subnet_passes(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("aa:bb:cc:dd:ee:01", "10.0.0.55")
        assert result is None

    def test_ip_outside_subnet_detected(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("aa:bb:cc:dd:ee:01", "10.0.1.55")
        assert result is not None


# ---------------------------------------------------------------------------
# 복합 위반
# ---------------------------------------------------------------------------

class TestCombinedViolation:
    def test_both_mac_and_ip_unauthorized(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("ff:ff:ff:ff:ff:ff", "172.16.0.99")
        assert result is not None
        assert "MAC" in result["reason"]
        assert "IP" in result["reason"]

    def test_violation_dict_structure(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("ff:ff:ff:ff:ff:ff", "172.16.0.99")
        assert "mac" in result
        assert "ip" in result
        assert "reason" in result
        assert "timestamp" in result
        assert isinstance(result["timestamp"], float)


# ---------------------------------------------------------------------------
# 엣지 케이스
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_authorized_lists_passes_all(self):
        """인가 목록이 모두 비어있으면 모든 디바이스 통과."""
        d = UnauthorizedDetector()
        d.load_policy({
            "enabled":            True,
            "authorized_macs":    [],
            "authorized_ips":     [],
            "authorized_subnets": [],
        })
        result = d.check("ff:ff:ff:ff:ff:ff", "1.2.3.4")
        assert result is None

    def test_empty_mac_string(self):
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("", "192.168.1.100")
        assert result is not None  # 빈 MAC은 인가 목록에 없음

    def test_empty_ip_string(self):
        """IP가 빈 문자열이면 MAC만으로 판단."""
        d = UnauthorizedDetector()
        d.load_policy(_policy())
        result = d.check("aa:bb:cc:dd:ee:01", "")
        assert result is None  # MAC 인가, IP 비어있으면 통과
