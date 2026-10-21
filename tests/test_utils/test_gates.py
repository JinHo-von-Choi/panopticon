"""출시 게이트 자체의 계약 시험.

게이트는 릴리스의 조건이다. 게이트가 조용히 약해지면 아무도 모르게
불일치가 통과한다. 여기서는 게이트가 **무엇을 검사하는지** 를 고정한다.

2026-10-22 실측: G0-21 은 예외 목록을 파일 이름으로 비교해서
`netwatcher/response/runtime.py` 같은 파일까지 계층 방향 검사에서
건너뛰었다. 계층 역전 게이트가 우회 가능했다.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from scripts.gates import (
    COMPOSITION_ROOTS,
    _is_composition_root,
    gate_layer_direction,
    gate_schema_parity,
)


# ── G0-21: 계층 방향 ───────────────────────────────────────────────

def test_composition_roots_are_relative_paths():
    """조립 지점은 netwatcher/ 기준 상대경로로 적는다."""
    for root in COMPOSITION_ROOTS:
        assert "/" in root or root.endswith(".py")
        assert not root.startswith("netwatcher/")

    assert "ingest/runtime.py" in COMPOSITION_ROOTS


@pytest.mark.parametrize(
    "path, expected",
    [
        ("netwatcher/app.py", True),
        ("netwatcher/native_console.py", True),
        ("netwatcher/ingest/runtime.py", True),
        # 같은 파일 이름이라도 조립 지점이 아니다.
        ("netwatcher/response/runtime.py", False),
        ("netwatcher/services/runtime.py", False),
        ("netwatcher/detection/runtime.py", False),
        ("netwatcher/web/server.py", False),
        ("netwatcher/storage/repositories.py", False),
    ],
)
def test_composition_root_matching_is_path_based(path, expected):
    """파일 이름이 아니라 경로로 판정한다."""
    assert _is_composition_root(PurePosixPath(path)) is expected


def test_layer_direction_gate_passes_on_current_tree():
    """현재 저장소에는 계층 역전이 없다."""
    result = gate_layer_direction()

    assert result.passed is True, result.detail
    assert any("offenders=0" in check for check in result.checks)


def test_layer_direction_gate_reports_its_roots():
    """게이트는 허용 지점을 결과에 남긴다 — 좁은 범위를 숨기지 않는다."""
    result = gate_layer_direction()

    roots = next(check for check in result.checks if check.startswith("roots="))
    assert roots == "roots=" + ",".join(sorted(COMPOSITION_ROOTS))


# ── G0-13: 스키마 정합성 ───────────────────────────────────────────

def test_schema_parity_gate_checks_both_directions():
    """정합성 게이트는 양방향을 본다."""
    result = gate_schema_parity()

    assert result.passed is True, result.detail
    assert any(check.startswith("parity=yes") for check in result.checks)
    assert any(check.startswith("reverse=yes") for check in result.checks)


def test_schema_parity_counts_tables_created_via_constants():
    """`op.execute(상수)` 로 만드는 표도 세야 한다.

    마이그레이션이 DDL 상수를 참조하면 그 DDL 은 마이그레이션 파일 안에
    없다. 정규식만 쓰면 표를 놓쳐 표 수를 과소계산한다 (32 vs 37).
    """
    result = gate_schema_parity()

    tables = next(int(check.split("=")[1]) for check in result.checks if check.startswith("tables="))
    assert tables >= 37, f"표 수가 과소계산되었다: {tables}"
