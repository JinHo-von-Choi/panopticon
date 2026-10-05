"""엔진 설정 엄격 검증 테스트 (PR 03).

이 테스트들이 고정하는 것은 "검증 경고"가 아니라 "거부"다. 각 항목은
이전 구현에서 조용히 통과해 런타임에 도달하던 값이다.
"""

from __future__ import annotations

import math

import pytest

from netwatcher.detection.validation import (
    RESERVED_KEYS,
    assert_valid_engine_config,
    validate_engine_config,
)

SCHEMA = {
    "enabled": (bool, True),
    "window_seconds": {"type": int, "default": 60, "min": 1, "max": 3600},
    "threshold": {"type": int, "default": 50, "min": 1, "max": 1000},
    "entropy_threshold": {"type": float, "default": 3.8, "min": 0.0, "max": 8.0},
    "cooldown_seconds": {"type": int, "default": 300, "min": 0, "max": 86400},
    "lateral_ports": {"type": list, "default": [22, 445]},
    "max_tracked_hosts": {"type": int, "default": 10000, "min": 1, "max": 1000000},
}


def _codes(violations) -> set[str]:
    return {v.code for v in violations}


# ------------------------------------------------------------------
# 기준 상태
# ------------------------------------------------------------------

def test_valid_config_passes():
    cfg = {
        "enabled": True,
        "window_seconds": 60,
        "threshold": 50,
        "entropy_threshold": 3.8,
        "cooldown_seconds": 300,
        "lateral_ports": [22, 445],
        "max_tracked_hosts": 10000,
    }
    assert validate_engine_config(SCHEMA, cfg) == []


def test_int_accepted_for_float_field():
    cfg = {**_valid(), "entropy_threshold": 4}
    assert validate_engine_config(SCHEMA, cfg) == []


# ------------------------------------------------------------------
# 1. 스키마 선언 검사
# ------------------------------------------------------------------

def test_undeclared_key_rejected():
    """스키마에 없는 키는 엔진에서 읽히지 않는다 → 조용히 무시되면 안 된다."""
    violations = validate_engine_config(SCHEMA, {**_valid(), "totally_unknown": 1})
    assert "V-001" in _codes(violations)


def test_reserved_keys_allowed_without_declaration():
    cfg = {**_valid(), "tick_interval": 2}
    assert all(k in RESERVED_KEYS for k in ("enabled", "tick_interval"))
    assert validate_engine_config(SCHEMA, cfg) == []


def test_missing_required_field_rejected():
    cfg = {**_valid()}
    cfg.pop("threshold")
    assert "V-002" in _codes(validate_engine_config(SCHEMA, cfg))


def test_partial_update_allows_missing_fields():
    cfg = {**_valid()}
    cfg.pop("threshold")
    assert validate_engine_config(SCHEMA, cfg, allow_partial=True) == []


def test_partial_update_still_rejects_unknown_keys():
    violations = validate_engine_config(
        SCHEMA, {"threshold": 10, "nope": 1}, allow_partial=True,
    )
    assert "V-001" in _codes(violations)


# ------------------------------------------------------------------
# 2. 타입 검사
# ------------------------------------------------------------------

def test_bool_rejected_for_int_field():
    """True 는 int 의 하위 타입이지만 설정 의미가 다르다(1 과 구분)."""
    violations = validate_engine_config(SCHEMA, {**_valid(), "threshold": True})
    assert "V-010" in _codes(violations)


def test_int_rejected_for_bool_field():
    violations = validate_engine_config(SCHEMA, {**_valid(), "enabled": 1})
    assert "V-010" in _codes(violations)


def test_str_rejected_for_int_field():
    assert "V-010" in _codes(validate_engine_config(SCHEMA, {**_valid(), "threshold": "50"}))


def test_wrong_container_type_rejected():
    violations = validate_engine_config(SCHEMA, {**_valid(), "lateral_ports": "22,445"})
    assert "V-010" in _codes(violations)


def test_null_rejected():
    assert "V-003" in _codes(validate_engine_config(SCHEMA, {**_valid(), "threshold": None}))


# ------------------------------------------------------------------
# 3. 유한성 검사
# ------------------------------------------------------------------

@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_inf_rejected(value):
    assert math.isnan(value) or math.isinf(value)
    violations = validate_engine_config(SCHEMA, {**_valid(), "entropy_threshold": value})
    assert "V-011" in _codes(violations)


# ------------------------------------------------------------------
# 4. 범위 검사
# ------------------------------------------------------------------

def test_below_minimum_rejected():
    assert "V-020" in _codes(validate_engine_config(SCHEMA, {**_valid(), "threshold": 0}))


def test_above_maximum_rejected():
    assert "V-021" in _codes(validate_engine_config(SCHEMA, {**_valid(), "threshold": 1001}))


def test_zero_duration_rejected():
    violations = validate_engine_config(SCHEMA, {**_valid(), "window_seconds": 0})
    assert "V-022" in _codes(violations)


def test_negative_duration_rejected():
    violations = validate_engine_config(SCHEMA, {**_valid(), "cooldown_seconds": -1})
    assert "V-022" in _codes(violations)


# ------------------------------------------------------------------
# 5. 누적 제한 검사
# ------------------------------------------------------------------

def test_cumulative_max_value_enforced():
    violations = validate_engine_config(SCHEMA, {**_valid(), "max_tracked_hosts": 2_000_000})
    assert "V-030" in _codes(violations)


def test_window_and_cooldown_product_enforced():
    """각각은 범위 안이지만 곱이 1년치를 넘으면 탐지창이 무한대가 된다."""
    cfg = {**_valid(), "window_seconds": 3600, "cooldown_seconds": 86400}
    assert "V-031" in _codes(validate_engine_config(SCHEMA, cfg))


def test_reasonable_window_product_passes():
    cfg = {**_valid(), "window_seconds": 60, "cooldown_seconds": 300}
    assert validate_engine_config(SCHEMA, cfg) == []


# ------------------------------------------------------------------
# 예외 경로 / 스키마 부재
# ------------------------------------------------------------------

def test_non_dict_config_rejected():
    violations = validate_engine_config(SCHEMA, ["not", "a", "dict"])
    assert "V-000" in _codes(violations)


def test_no_schema_skips_key_check():
    """스키마가 없는 엔진은 키 선언 대상이 아니다."""
    assert validate_engine_config(None, {"anything": 1}) == []
    assert validate_engine_config({}, {"anything": 1}) == []


def test_assert_raises_with_engine_name():
    with pytest.raises(ValueError) as exc:
        assert_valid_engine_config(SCHEMA, {**_valid(), "nope": 1}, engine_name="port_scan")
    assert "port_scan" in str(exc.value)


def test_assert_passes_silently():
    assert_valid_engine_config(SCHEMA, _valid(), engine_name="port_scan")


def test_multiple_violations_reported_together():
    violations = validate_engine_config(SCHEMA, {
        "enabled": True,
        "window_seconds": 0,
        "threshold": 99999,
        "unknown": 1,
    })
    assert len(violations) >= 3
    assert {"V-001", "V-021", "V-022"} <= _codes(violations)


def _valid() -> dict:
    return {
        "enabled": True,
        "window_seconds": 60,
        "threshold": 50,
        "entropy_threshold": 3.8,
        "cooldown_seconds": 300,
        "lateral_ports": [22, 445],
        "max_tracked_hosts": 10000,
    }
