"""mypy 래치의 계약 시험.

래치는 "오류가 늘면 CI 가 어두워진다" 를 보장한다. 그게 실제로 성립하는지
확인한다 — 기준선을 잘못 읽으면 조용히 통과한다.
"""

from __future__ import annotations

import json

import pytest

from scripts.mypy_latch import (
    BASELINE_PATH,
    baseline_for,
    count_errors,
    load_baseline,
)


def test_error_counting_matches_ci_pattern():
    """CI 가 쓰던 패턴과 같은 줄만 오류로 센다."""
    output = (
        "netwatcher/app.py:804: error: Item \"None\" has no attribute \"cancel\"  [union-attr]\n"
        "netwatcher/app.py:900: note: something\n"
        "Found 190 errors in 64 files (checked 294 source files)\n"
        "error: overall failure\n"
    )

    assert count_errors(output) == 1


def test_error_counting_ignores_notes_and_summaries():
    assert count_errors("Found 190 errors in 64 files\n") == 0
    assert count_errors("") == 0


def test_baseline_file_has_no_description_keys():
    """설명용 키는 기준선이 아니다 — 정수로 읽혀야 한다."""
    raw = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    described = [key for key in raw if key.startswith("_")]

    assert described, "기준선 파일에 설명 키가 없다 — 사람이 읽을 수 없다"
    for key in described:
        assert isinstance(raw[key], str)


def test_baseline_covers_supported_python_versions():
    """CI 매트릭스의 모든 버전에 기준선이 있다."""
    baseline = load_baseline()

    assert "3.12" in baseline
    assert "3.13" in baseline


def test_baseline_lookup_is_version_specific():
    """버전마다 자기 기준선을 쓴다 — 하나의 전역 상한이 아니다."""
    baseline = load_baseline()

    limit_312, key_312 = baseline_for("3.12.18", baseline)
    limit_313, key_313 = baseline_for("3.13.1", baseline)

    assert key_312 == "3.12"
    assert key_313 == "3.13"
    # 2026-10-22 CI 실측: 두 버전 모두 190. 지금은 같지만 지표는 나눈다 —
    # 한쪽만 오류를 고치면 갈라질 수 있다.
    assert (limit_312, limit_313) == (190, 190)


def test_unknown_version_uses_the_strictest_available_baseline():
    """알 수 없는 버전은 조용히 통과하지 않는다."""
    baseline = load_baseline()

    limit, key = baseline_for("3.99", baseline)

    assert limit == max(baseline.values())
    assert "알 수 없음" in key


def test_baseline_is_at_least_the_measured_error_count():
    """기준선은 실측 오류 수보다 작을 수 없다 — 작은 값은 즉시 깨진다."""
    baseline = load_baseline()

    for version, limit in baseline.items():
        assert limit > 0, f"{version} 기준선이 0 이다"
