"""제안 대비 프로브 — 같은 입력에 기준 계약과 후보 계약을 각각 실행한다.

순수 함수다. DB도 네트워크도 없다. 그래서 같은 입력에는 같은 결과가 나온다.

프로브는 판정을 하지 않는다. **관측이 어떻게 달라지는지** 만 말한다. 경보
감소는 오탐 감소의 증거가 아니다 — 정상 여부는 담당자가 확인한다.

비교하지 못한 경우에는 사유를 남긴다. 사유 없는 미실행은 허용되지 않는다.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from netwatcher import __version__
from netwatcher.replay.contract import (
    MODELLED_PARAMS,
    REASON_BUDGET_EXCEEDED,
    REASON_ENGINE_UNSUPPORTED,
    REASON_FEATURE_MISSING,
    AnalysisContract,
    unsupported_reason,
)
from netwatcher.replay.service import MAX_SOURCE_BYTES, diff_sides, execute_side
from netwatcher.replay.trace import build_trace

PROBE_COMPARED = "compared"
PROBE_SKIPPED = "skipped"

# 프로브가 입력에 대해 못 한 일.
REASON_TRACE_UNAVAILABLE = "trace_unavailable"

# 후보를 제시할 때 쓰는 중립 라벨. 출처는 감사 기록에만 남는다.
CANDIDATE_LABEL = "CAND-1"

NOTICE = (
    "관측 차이만 보인다. 경보 감소는 오탐 감소의 증거가 아니다 — "
    "정상 여부는 담당자가 확인한다."
)

DEFAULT_VERSIONS = {
    "build_version": __version__,
    "config_version": "unknown",
    "feed_version": "unknown",
    "whitelist_version": "unknown",
    "normalizer_version": "unknown",
}


def _reason(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


def _empty_counts() -> dict[str, int]:
    return {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": 0,
        "removed_unreproducible": 0,
    }


def skipped(engine: str, code: str, detail: str) -> dict[str, Any]:
    """비교하지 못한 결과. 사유가 반드시 붙는다."""
    return {
        "status": PROBE_SKIPPED,
        "comparable": False,
        "engine": engine,
        "candidate_label": CANDIDATE_LABEL,
        "input_count": 0,
        "input_hash": "",
        "counts": _empty_counts(),
        "added": [],
        "removed": [],
        "changed": [],
        "reasons": [_reason(code, detail)],
        "notice": NOTICE,
    }


def split_removals(
    removed: Sequence[Mapping[str, Any]],
) -> tuple[list[dict], list[dict]]:
    """재현 불가로 사라진 관측과 비교 가능한 감소를 나눈다.

    재현 불가로 사라진 것은 감소가 아니다 — 경보가 줄었다는 뜻이 아니라
    비교할 수 없었다는 뜻이다. 그래서 두 갈래로 나눈다.
    """
    unreproducible = [dict(item) for item in removed if item.get("removal_cause")]
    reproducible = [dict(item) for item in removed if not item.get("removal_cause")]
    return reproducible, unreproducible


def run_probe(
    *,
    engine: str,
    records: Sequence[Mapping[str, Any]] | None,
    before_params: Mapping[str, Any] | None,
    candidate_params: Mapping[str, Any] | None,
    versions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """기준 설정과 후보 설정을 같은 입력에 대해 실행해 관측 차이를 낸다.

    ``records`` 는 탐지 전 특징값 레코드 목록이다. 비어 있으면 비교할 입력이
    없으므로 ``trace_unavailable`` 사유를 남긴다.
    """
    if not records:
        return skipped(
            engine, REASON_TRACE_UNAVAILABLE,
            "비교할 입력이 없다 — 재현 입력이 있어야 관측 차이를 낼 수 있다",
        )
    if not all(isinstance(record, Mapping) for record in records):
        return skipped(
            engine, REASON_TRACE_UNAVAILABLE,
            "비교 입력의 형식이 올바르지 않다 — 특징값 레코드 목록이어야 한다",
        )

    unsupported = unsupported_reason(engine)
    if unsupported is not None:
        return skipped(
            engine, REASON_ENGINE_UNSUPPORTED,
            f"{engine} 은 재현 분석 대상이 아니다",
        )

    before = dict(before_params or {})
    candidate = dict(candidate_params or {})
    modelled = MODELLED_PARAMS.get(engine, set())
    changed = {
        key for key in before.keys() | candidate.keys()
        if before.get(key) != candidate.get(key)
    }
    unmodelled = changed - modelled
    if unmodelled:
        return skipped(
            engine, REASON_FEATURE_MISSING,
            f"{engine}: 모델링되지 않은 파라미터가 바뀌었다: "
            f"{', '.join(sorted(unmodelled))}",
        )

    trace = build_trace([dict(record) for record in records], [engine], complete=True)
    source_bytes = trace.size_bytes
    if source_bytes > MAX_SOURCE_BYTES:
        return skipped(
            engine, REASON_BUDGET_EXCEEDED,
            f"입력 {source_bytes} B 가 상한 {MAX_SOURCE_BYTES} B 를 넘었다",
        )

    contract_versions = dict(DEFAULT_VERSIONS)
    contract_versions.update(dict(versions or {}))
    baseline_contract = AnalysisContract(
        engine_params=before,
        build_version=contract_versions["build_version"],
        config_version=contract_versions["config_version"],
        feed_version=contract_versions["feed_version"],
        whitelist_version=contract_versions["whitelist_version"],
        normalizer_version=contract_versions["normalizer_version"],
    )
    candidate_contract = AnalysisContract(
        engine_params=candidate,
        build_version=contract_versions["build_version"],
        config_version=contract_versions["config_version"],
        feed_version=contract_versions["feed_version"],
        whitelist_version=contract_versions["whitelist_version"],
        normalizer_version=contract_versions["normalizer_version"],
    )

    baseline, baseline_reasons = execute_side(
        trace, baseline_contract, source_bytes=source_bytes,
    )
    candidate_result, candidate_reasons = execute_side(
        trace, candidate_contract, source_bytes=source_bytes,
    )
    reasons = list(baseline_reasons) + list(candidate_reasons)
    diff = diff_sides(baseline, candidate_result, reasons)

    # 재현 불가로 사라진 관측은 감소가 아니다. 감소로 세지 않는다.
    removed = list(diff.get("removed") or [])
    reproducible, unreproducible = split_removals(removed)
    counts = dict(diff.get("counts") or {})
    counts["removed"] = len(reproducible)
    counts["removed_unreproducible"] = len(unreproducible)

    comparable = not unreproducible and not [
        reason for reason in reasons if reason.get("code") == REASON_FEATURE_MISSING
    ]
    return {
        "status": PROBE_COMPARED,
        "comparable": comparable,
        "engine": engine,
        "candidate_label": CANDIDATE_LABEL,
        "baseline_params": before,
        "candidate_params": candidate,
        "input_count": trace.input_count,
        "input_hash": trace.input_hash(),
        "counts": counts,
        "added": list(diff.get("added") or []),
        "removed": reproducible,
        "changed": list(diff.get("changed") or []),
        "reasons": list(diff.get("non_comparable_reasons") or reasons),
        "notice": NOTICE,
    }
