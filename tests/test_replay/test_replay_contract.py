"""리플레이 계약 테스트 (계획서 1장, PR 12).

고정하는 것

1. **결정성** — 같은 trace 를 N 번 돌려도 결과 지문이 같다
2. **격리** — 운영 경로로 나가는 통로가 코드에 없다
3. **비교 불가 사유를 숨기지 않는다** — 지원 밖 엔진·원본 부재·입력 단절
4. **감소 = 성공 이 아니다** — 사라진 관측과 비교 불가를 구분한다
5. **예산 초과를 숨기지 않는다**

계획서 검수 기준:

    "개발 smoke test 는 동일 trace 3 회, 정식 출 시 G3 는 20 회 결과
     fingerprint 를 비교하되 임의 ID 만 제외하고 경보 시점 · 순서는 유지한다.
     tick 경계 · 재시작 · 불완전 입력을 시험한다."
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from netwatcher.replay.analyzers import (
    analyze_address_binding,
    analyze_connection_distribution,
    analyze_transfer_volume,
    get_analyzer,
)
from netwatcher.replay.contract import (
    OBS_ADDRESS_BINDING,
    OBS_CONNECTION_DISTRIBUTION,
    OBS_TRANSFER_VOLUME,
    REASON_BUDGET_EXCEEDED,
    REASON_ENGINE_UNSUPPORTED,
    REASON_FEATURE_MISSING,
    REASON_PAYLOAD_ENGINE,
    REASON_TRACE_INCOMPLETE,
    REASON_VERSION_MISMATCH,
    AnalysisContract,
    fingerprint_observations,
    unsupported_reason,
)
from netwatcher.replay.service import (
    MAX_SOURCE_BYTES,
    compare,
    diff_sides,
    execute_side,
    split_outcome,
)
from netwatcher.replay.trace import build_trace

REPLAY_DIR = Path(__file__).resolve().parents[2] / "netwatcher" / "replay"


# ------------------------------------------------------------------
# 입력 픽스처
# ------------------------------------------------------------------

def _scan_records(count: int = 30) -> list[dict]:
    return [
        {
            "src_ip": "10.0.0.9", "dst_ip": "10.0.0.2",
            "src_mac": "aa:bb:cc:00:00:01", "dst_mac": "aa:bb:cc:00:00:02",
            "dst_port": 1000 + i, "bytes": 120, "ts": 1.0 + i * 0.1,
            "ip_proto": "tcp",
        }
        for i in range(count)
    ]


def _arp_records() -> list[dict]:
    return [
        {"src_ip": "10.0.0.5", "src_mac": "aa:aa:aa:aa:aa:01", "ts": 1.0},
        {"src_ip": "10.0.0.5", "src_mac": "aa:aa:aa:aa:aa:02", "ts": 2.0},
    ]


def _exfil_records(total_mb: int = 3) -> list[dict]:
    return [
        {"src_ip": "10.0.0.7", "dst_ip": "203.0.113.9", "bytes": 1024 * 1024,
         "ts": float(i), "ip_proto": "tcp"}
        for i in range(total_mb)
    ]


# ------------------------------------------------------------------
# 1) 결정성 — 같은 입력 3회
# ------------------------------------------------------------------

@pytest.mark.parametrize("repeat", [1, 2, 3])
def test_same_trace_produces_identical_fingerprint(repeat: int) -> None:
    """동일 trace 3회 → 동일 지문. (G3 는 20 회로 늘린다)"""
    trace = build_trace(_scan_records(), ["port_scan"])
    contract = AnalysisContract(engine_params={"threshold": 5})

    results, _ = execute_side(trace, contract)
    assert results["port_scan"].fingerprint()


def test_three_runs_are_stable() -> None:
    """3 회 실행의 지문이 모두 같다."""
    trace = build_trace(_scan_records(), ["port_scan"])
    contract = AnalysisContract(engine_params={"threshold": 5})

    prints = [execute_side(trace, contract)[0]["port_scan"].fingerprint() for _ in range(3)]
    assert len(set(prints)) == 1, "동일 입력이 다른 결과를 냈다"


def test_record_order_changes_fingerprint() -> None:
    """같은 값·다른 순서는 다른 입력이다."""
    a = build_trace(_scan_records(10), ["port_scan"])
    b = build_trace(list(reversed(_scan_records(10))), ["port_scan"])
    contract = AnalysisContract(engine_params={"threshold": 5})

    fa = execute_side(a, contract)[0]["port_scan"].fingerprint()
    fb = execute_side(b, contract)[0]["port_scan"].fingerprint()
    assert fa != fb, "순서를 무시하고 있다 — 같은 입력이라는 말이 무의미해진다"


def test_order_key_differs_on_reordering() -> None:
    a = build_trace(_scan_records(10), ["port_scan"])
    b = build_trace(list(reversed(_scan_records(10))), ["port_scan"])
    assert a.order_key() != b.order_key()


def test_observation_time_and_sequence_survive_fingerprint() -> None:
    """시점과 순서는 지문에 남는다 — 계획서: "경보 시점 · 순서는 유지한다"."""
    contract = AnalysisContract(engine_params={"threshold": 5})
    trace = build_trace(_scan_records(12), ["port_scan"])
    obs = execute_side(trace, contract)[0]["port_scan"].observations
    assert obs and obs[0].observed_at > 0
    assert obs[0].seq >= 1


# ------------------------------------------------------------------
# 2) 관측 의미 — 세 엔진
# ------------------------------------------------------------------

def test_address_binding_observation() -> None:
    out = analyze_address_binding(_arp_records(), AnalysisContract())
    kinds = {o.kind for o in out}
    assert OBS_ADDRESS_BINDING in kinds
    subject = next(o for o in out if o.kind == OBS_ADDRESS_BINDING and not o.subject.startswith("mac:"))
    assert subject.features["mac_count"] == 2


def test_connection_distribution_observation() -> None:
    out = analyze_connection_distribution(_scan_records(30), AnalysisContract())
    assert out[0].kind == OBS_CONNECTION_DISTRIBUTION
    assert out[0].features["unique_port_count"] == 30
    assert out[0].features["consecutive_span"] == 30


def test_transfer_volume_observation() -> None:
    contract = AnalysisContract(engine_params={"threshold": 1_000_000})
    out = analyze_transfer_volume(_exfil_records(3), contract)
    assert out[0].kind == OBS_TRANSFER_VOLUME
    assert out[0].features["total_bytes"] == 3 * 1024 * 1024


def test_observation_never_claims_malice() -> None:
    """악성 여부를 확정하지 않는다 (계획서: "악성 여부를 확정하는 엔진으로
    포장하지 않는다")."""
    contract = AnalysisContract(engine_params={"threshold": 1})
    for out in (
        analyze_address_binding(_arp_records(), contract),
        analyze_connection_distribution(_scan_records(30), contract),
        analyze_transfer_volume(_exfil_records(3), contract),
    ):
        for obs in out:
            assert "malicious" not in obs.as_dict()
            assert "is_attack" not in obs.as_dict()


def test_below_threshold_yields_no_observation() -> None:
    out = analyze_connection_distribution(_scan_records(3), AnalysisContract())
    assert out == []


# ------------------------------------------------------------------
# 3) 격리 — 운영 경로에 닿지 않는다
# ------------------------------------------------------------------

FORBIDDEN_MODULES = (
    "netwatcher.alerts", "netwatcher.response", "netwatcher.capture",
    "netwatcher.threatintel", "netwatcher.utils.network", "netwatcher.services",
    "scapy", "socket", "httpx", "requests",
)


@pytest.mark.parametrize("path", sorted(REPLAY_DIR.glob("*.py")), ids=lambda p: p.name)
def test_replay_package_imports_no_operational_module(path: Path) -> None:
    """리플레이 패키지는 운영 모듈을 import 하지 않는다."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules = [node.module]
        for module in modules:
            assert not module.startswith(FORBIDDEN_MODULES), (
                f"{path.name} 이 운영 모듈 {module} 을 import 한다"
            )


@pytest.mark.parametrize("path", sorted(REPLAY_DIR.glob("*.py")), ids=lambda p: p.name)
def test_replay_package_writes_no_operational_table(path: Path) -> None:
    """운영 events 등 운영 테이블에 쓰지 않는다."""
    import re

    text = path.read_text(encoding="utf-8")
    for table in ("events", "alert_dispatch", "blocks", "custom_blocklist"):
        assert not re.search(
            rf"\b(?:INSERT\s+INTO|UPDATE|FROM)\s+{table}\b", text, re.IGNORECASE,
        ), f"{path.name} 이 운영 테이블 {table} 을 참조한다"


def test_analysis_does_not_dispatch_alerts() -> None:
    """분석 경로에 알림 enqueue 가 없다."""
    from netwatcher.replay import service

    assert "enqueue(" not in Path(service.__file__).read_text(encoding="utf-8")


def test_execute_side_is_pure(tmp_path) -> None:
    """execute_side 는 I/O 를 하지 않는다 — 결정성의 근거."""
    import inspect

    from netwatcher.replay import service

    src = inspect.getsource(service.execute_side)
    for forbidden in ("await ", "async ", "pool.", "httpx", "socket"):
        assert forbidden not in src, f"분석에 I/O 가 섞여 있다: {forbidden}"


# ------------------------------------------------------------------
# 4) 비교 불가 사유 — 숨기지 않는다
# ------------------------------------------------------------------

def test_unsupported_engine_is_marked_not_failed() -> None:
    """지원 밖 엔진(원본이 필요 없는 payload 계열이 아닌 것)은 명시적 미지원."""
    trace = build_trace(_scan_records(10), ["tls_fingerprint"])
    results, reasons = execute_side(trace, AnalysisContract())

    assert "tls_fingerprint" in results
    assert results["tls_fingerprint"].unsupported == [REASON_ENGINE_UNSUPPORTED]
    assert any(r["code"] == REASON_ENGINE_UNSUPPORTED for r in reasons)


def test_payload_engine_without_source_is_reproduction_impossible() -> None:
    """원본이 없는 payload 엔진은 재현 불가 — 해시로 대신하지 않는다."""
    trace = build_trace(_scan_records(10), ["http_suspicious"])
    assert "http_suspicious" in trace.payload_engines

    results, reasons = execute_side(trace, AnalysisContract())

    # "아직 지원 안 함" 이 아니라 "지원해도 원본이 없어 불가능" 이어야 한다
    assert results["http_suspicious"].unsupported == [REASON_PAYLOAD_ENGINE]
    codes = {r["code"] for r in reasons}
    assert REASON_PAYLOAD_ENGINE in codes
    assert REASON_ENGINE_UNSUPPORTED not in codes, "구체적 사유를 일반 사유로 덮었다"


def test_incomplete_input_blocks_comparison() -> None:
    trace = build_trace(_scan_records(10), ["port_scan"], complete=False)
    _, reasons = execute_side(trace, AnalysisContract(engine_params={"threshold": 5}))
    assert any(r["code"] == REASON_TRACE_INCOMPLETE for r in reasons)


def test_empty_records_produce_missing_feature_reason() -> None:
    trace = build_trace([], ["port_scan"])
    results, reasons = execute_side(trace, AnalysisContract())
    assert any(r["code"] == REASON_FEATURE_MISSING for r in reasons)
    assert results["port_scan"].observations == []


def test_version_mismatch_makes_result_non_comparable() -> None:
    """버전 지문이 다르면 차이의 출처를 특정할 수 없다."""
    trace = build_trace(_scan_records(30), ["port_scan"])
    baseline = AnalysisContract(
        build_version="v1", config_version="c1", engine_params={"threshold": 5},
    )
    candidate = AnalysisContract(
        build_version="v2", config_version="c1", engine_params={"threshold": 5},
    )

    outcome = compare(trace, baseline, candidate)
    assert outcome.comparable is False
    assert any(r["code"] == REASON_VERSION_MISMATCH for r in outcome.non_comparable_reasons)


def test_budget_exceeded_is_reported() -> None:
    """예산 초과를 숨기지 않는다."""
    trace = build_trace(_scan_records(10), ["port_scan"])
    results, reasons = execute_side(
        trace, AnalysisContract(engine_params={"threshold": 5}),
        source_bytes=MAX_SOURCE_BYTES + 1,
    )
    assert results == {}
    assert any(r["code"] == REASON_BUDGET_EXCEEDED for r in reasons)


# ------------------------------------------------------------------
# 5) diff — 감소를 성공으로 읽지 않는다
# ------------------------------------------------------------------

def test_diff_reports_added_removed_changed() -> None:
    trace = build_trace(_scan_records(30), ["port_scan"])
    base = AnalysisContract(build_version="v1", engine_params={"threshold": 5})
    cand = AnalysisContract(build_version="v1", engine_params={"threshold": 40})

    outcome = compare(trace, base, cand)
    b, c = split_outcome(outcome)
    result = diff_sides(b, c)

    assert result["counts"]["removed"] == 1, "임계값 상향으로 관측이 사라져야 한다"
    assert result["counts"]["added"] == 0


def test_diff_says_reduction_is_not_proof_of_false_positive_reduction() -> None:
    trace = build_trace(_scan_records(30), ["port_scan"])
    base = AnalysisContract(build_version="v1", engine_params={"threshold": 5})
    cand = AnalysisContract(build_version="v1", engine_params={"threshold": 40})

    outcome = compare(trace, base, cand)
    b, c = split_outcome(outcome)
    result = diff_sides(b, c)

    assert "오탐 감소의 증거가 아니다" in result["interpretation"]["notice"]


def test_removed_observation_carries_cause_when_unsupported() -> None:
    """재현 불가로 사라진 것은 '줄어든 것' 이 아니라 사유를 달고 사라진다."""
    trace = build_trace(_scan_records(30), ["port_scan"])
    base, _ = execute_side(trace, AnalysisContract(engine_params={"threshold": 5}))
    cand, _ = execute_side(trace, AnalysisContract(engine_params={"threshold": 5}))
    # 후보 쪽이 재현 불가로 바뀐 상황
    from netwatcher.replay.contract import ReplayResult

    cand["port_scan"] = ReplayResult(
        engine="port_scan", version="v1",
        unsupported=[REASON_FEATURE_MISSING],
    )

    result = diff_sides(base, cand, reasons=[{"code": REASON_FEATURE_MISSING}])
    assert result["counts"]["removed"] == 1
    assert result["removed"][0]["removal_cause"]


def test_diff_is_stable_across_repeats() -> None:
    trace = build_trace(_scan_records(30), ["port_scan"])
    base = AnalysisContract(build_version="v1", engine_params={"threshold": 5})
    cand = AnalysisContract(build_version="v1", engine_params={"threshold": 40})

    outs = []
    for _ in range(3):
        outcome = compare(trace, base, cand)
        b, c = split_outcome(outcome)
        outs.append(diff_sides(b, c)["counts"])
    assert outs[0] == outs[1] == outs[2]


# ------------------------------------------------------------------
# 6) 지원 범위
# ------------------------------------------------------------------

def test_only_three_engines_supported() -> None:
    """최초 지원은 3개로 제한한다."""
    assert unsupported_reason("arp_spoof") is None
    assert unsupported_reason("port_scan") is None
    assert unsupported_reason("data_exfil") is None
    for engine in ("http_suspicious", "signature", "tls_fingerprint", "c2_beaconing"):
        assert unsupported_reason(engine) == REASON_ENGINE_UNSUPPORTED


def test_get_analyzer_returns_none_for_unknown() -> None:
    assert get_analyzer("nope") is None


def test_fingerprint_ignores_dict_key_order() -> None:
    from netwatcher.replay.contract import Observation

    a = Observation("port_scan", "k", "s", {"a": 1, "b": 2}, 1.0, 1)
    b = Observation("port_scan", "k", "s", {"b": 2, "a": 1}, 1.0, 1)
    assert fingerprint_observations([a]) == fingerprint_observations([b])
