"""Tests for device risk scorer (pure function, no I/O)."""

from datetime import datetime, timedelta, timezone

import pytest

from netwatcher.inventory.risk_scorer import RiskAssessment, assess


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(hours_ago: float = 48.0) -> str:
    """UTC ISO 문자열 반환 — 기본 48시간 전 (신규 기기 아님)."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


def _device(**kw) -> dict:
    """기본값이 설정된 '완전히 안전한' 기기 dict를 생성한다."""
    base: dict = {
        "mac_address": "aa:bb:cc:dd:ee:01",
        "is_known":    True,
        "device_type": "pc",
        "hostname":    "workstation-01",
        "open_ports":  [],
        "first_seen":  _ts(hours_ago=72),
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

class TestReturnType:
    def test_returns_risk_assessment(self):
        result = assess(_device())
        assert isinstance(result, RiskAssessment)

    def test_has_score_level_factors(self):
        result = assess(_device())
        assert hasattr(result, "score")
        assert hasattr(result, "level")
        assert hasattr(result, "factors")


# ---------------------------------------------------------------------------
# Zero-risk baseline
# ---------------------------------------------------------------------------

class TestZeroRisk:
    def test_known_pc_with_hostname_no_ports_is_low(self):
        """등록된 PC, 호스트명 있음, 포트 없음 → 위험 없음 → low."""
        result = assess(_device())
        assert result.score == 0
        assert result.level == "low"
        assert result.factors == []


# ---------------------------------------------------------------------------
# Individual risk factors
# ---------------------------------------------------------------------------

class TestUnregistered:
    def test_unknown_device_adds_20(self):
        result = assess(_device(is_known=False))
        assert result.score == 20

    def test_factor_name(self):
        result = assess(_device(is_known=False))
        names = [f.name for f in result.factors]
        assert "unregistered" in names


class TestUnknownType:
    def test_unknown_type_adds_10(self):
        result = assess(_device(device_type="unknown"))
        assert result.score == 10

    def test_missing_type_key_treated_as_unknown(self):
        d = _device()
        d.pop("device_type")
        result = assess(d)
        assert result.score == 10


class TestNoHostname:
    def test_empty_hostname_adds_8(self):
        result = assess(_device(hostname=""))
        assert result.score == 8

    def test_none_hostname_adds_8(self):
        result = assess(_device(hostname=None))
        assert result.score == 8

    def test_na_string_adds_8(self):
        result = assess(_device(hostname="N/A"))
        assert result.score == 8

    def test_valid_hostname_no_score(self):
        result = assess(_device(hostname="router.local"))
        assert result.score == 0


class TestDangerousPorts:
    def test_one_dangerous_port_adds_15(self):
        result = assess(_device(open_ports=[23]))  # Telnet
        assert result.score == 15

    def test_two_dangerous_ports_adds_30(self):
        result = assess(_device(open_ports=[21, 23]))
        assert result.score == 30

    def test_three_dangerous_ports_capped_at_40(self):
        # 3 × 15 = 45 → 클램핑 → 40
        result = assess(_device(open_ports=[21, 23, 69]))
        assert result.score == 40

    def test_non_dangerous_port_no_score(self):
        result = assess(_device(open_ports=[80, 443, 8080]))
        assert result.score == 0

    def test_factor_name(self):
        result = assess(_device(open_ports=[3389]))
        names = [f.name for f in result.factors]
        assert "dangerous_ports" in names


class TestManyPorts:
    def test_exactly_5_ports_no_penalty(self):
        result = assess(_device(open_ports=[80, 443, 22, 8080, 8443]))
        assert result.score == 0

    def test_6_ports_adds_10(self):
        result = assess(_device(open_ports=[80, 443, 22, 8080, 8443, 9200]))
        assert result.score == 10

    def test_factor_name(self):
        result = assess(_device(open_ports=list(range(6))))
        names = [f.name for f in result.factors]
        assert "many_ports" in names


class TestNewDevice:
    def test_device_2h_old_adds_10(self):
        result = assess(_device(first_seen=_ts(hours_ago=2)))
        assert result.score == 10

    def test_device_25h_old_no_score(self):
        result = assess(_device(first_seen=_ts(hours_ago=25)))
        assert result.score == 0

    def test_exactly_24h_old_no_score(self):
        result = assess(_device(first_seen=_ts(hours_ago=24.01)))
        assert result.score == 0

    def test_factor_name(self):
        result = assess(_device(first_seen=_ts(hours_ago=1)))
        names = [f.name for f in result.factors]
        assert "new_device" in names

    def test_invalid_first_seen_ignored(self):
        """파싱 불가능한 날짜는 조용히 무시한다."""
        result = assess(_device(first_seen="NOT_A_DATE", hostname="ok"))
        assert result.score == 0

    def test_none_first_seen_ignored(self):
        result = assess(_device(first_seen=None))
        assert result.score == 0


# ---------------------------------------------------------------------------
# Level thresholds
# ---------------------------------------------------------------------------

class TestRiskLevels:
    def test_score_0_is_low(self):
        assert assess(_device()).level == "low"

    def test_score_below_30_is_low(self):
        # is_known=False (+20) → score=20 → low
        assert assess(_device(is_known=False)).level == "low"

    def test_score_30_is_medium(self):
        # is_known=False (+20) + unknown_type (+10) = 30 → medium
        result = assess(_device(is_known=False, device_type="unknown"))
        assert result.score == 30
        assert result.level == "medium"

    def test_score_60_is_high(self):
        # is_known=False (+20) + unknown_type (+10) + no_hostname (+8) +
        # new_device (+10) + dangerous_port (+15) = 63 → high
        result = assess(_device(
            is_known=False,
            device_type="unknown",
            hostname="",
            open_ports=[23],
            first_seen=_ts(hours_ago=1),
        ))
        assert result.score >= 60
        assert result.level == "high"


# ---------------------------------------------------------------------------
# Score capping
# ---------------------------------------------------------------------------

class TestScoreCap:
    def test_total_capped_at_100(self):
        result = assess(_device(
            is_known=False,
            device_type="unknown",
            hostname="",
            open_ports=[21, 23, 69, 161, 2375, 3389, 5900],  # 7 × 15 = 105, capped 40
            first_seen=_ts(hours_ago=1),
        ))
        # 20+10+8+40+10+10 = 98 — 100 이하
        assert result.score <= 100
