"""제안 대비 프로브 테스트.

프로브는 판정을 하지 않는다. 같은 입력에 대한 기준·후보의 **관측 차이** 만
말한다. 비교하지 못한 경우에는 사유를 남긴다 — 사유 없는 미실행은 허용되지
않는다.
"""

from __future__ import annotations

import pytest

from netwatcher.detection.probe import (
    CANDIDATE_LABEL,
    PROBE_COMPARED,
    PROBE_SKIPPED,
    REASON_TRACE_UNAVAILABLE,
    run_probe,
    split_removals,
)
from netwatcher.replay.contract import (
    REASON_ENGINE_UNSUPPORTED,
    REASON_FEATURE_MISSING,
)


def _records(ports=(22, 23, 24), src="10.0.0.5"):
    return [
        {"src_ip": src, "dst_port": port, "ts": 1000.0 + index}
        for index, port in enumerate(ports)
    ]


class TestSkipped:
    """비교하지 못하면 사유를 남긴다."""

    def test_without_input_reports_trace_unavailable(self):
        result = run_probe(
            engine="port_scan", records=[],
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        assert result["status"] == PROBE_SKIPPED
        assert result["comparable"] is False
        assert result["reasons"][0]["code"] == REASON_TRACE_UNAVAILABLE
        assert result["counts"]["added"] == 0

    def test_unsupported_engine_reports_engine_unsupported(self):
        result = run_probe(
            engine="dns_anomaly", records=_records(),
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        assert result["status"] == PROBE_SKIPPED
        assert result["reasons"][0]["code"] == REASON_ENGINE_UNSUPPORTED

    def test_unmodelled_parameter_change_is_not_compared(self):
        result = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 5}, candidate_params={"threshold": 5, "window_seconds": 30},
        )
        assert result["status"] == PROBE_SKIPPED
        assert result["reasons"][0]["code"] == REASON_FEATURE_MISSING

    def test_malformed_input_is_not_compared(self):
        result = run_probe(
            engine="port_scan", records=["not a record"],
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        assert result["status"] == PROBE_SKIPPED
        assert result["reasons"][0]["code"] == REASON_TRACE_UNAVAILABLE


class TestCompared:
    """같은 입력에 대한 기준·후보 관측 차이."""

    def test_lowered_threshold_adds_observation(self):
        result = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        assert result["status"] == PROBE_COMPARED
        assert result["counts"]["added"] == 1
        assert result["counts"]["removed"] == 0
        assert result["added"][0]["subject"] == "10.0.0.5"

    def test_raised_threshold_removes_observation(self):
        result = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 2}, candidate_params={"threshold": 5},
        )
        assert result["status"] == PROBE_COMPARED
        assert result["counts"]["removed"] == 1
        assert result["counts"]["removed_unreproducible"] == 0

    def test_same_parameters_produce_no_difference(self):
        result = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 2}, candidate_params={"threshold": 2},
        )
        assert result["status"] == PROBE_COMPARED
        assert result["counts"]["added"] == 0
        assert result["counts"]["removed"] == 0
        assert result["counts"]["unchanged"] == 1

    def test_result_carries_neutral_candidate_label(self):
        result = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        assert result["candidate_label"] == CANDIDATE_LABEL

    def test_same_input_gives_same_result(self):
        first = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        second = run_probe(
            engine="port_scan", records=_records(),
            before_params={"threshold": 5}, candidate_params={"threshold": 2},
        )
        assert first["input_hash"] == second["input_hash"]
        assert first["counts"] == second["counts"]


class TestRemovalSplit:
    """재현 불가로 사라진 것은 감소가 아니다."""

    def test_unreproducible_removal_is_separated(self):
        removed = [
            {"engine": "port_scan", "subject": "10.0.0.5"},
            {"engine": "port_scan", "subject": "10.0.0.6", "removal_cause": ["trace_incomplete"]},
        ]
        reproducible, unreproducible = split_removals(removed)
        assert [item["subject"] for item in reproducible] == ["10.0.0.5"]
        assert [item["subject"] for item in unreproducible] == ["10.0.0.6"]
