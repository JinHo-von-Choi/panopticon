"""ReplayService — 격리된 오프라인 재실행과 두 버전 비교 (계획서 1장).

이 모듈이 **하지 않는 것** 이 이 장치의 신뢰 근거다.

- 운영 ``AlertDispatcher`` 를 호출하지 않는다
- 방화벽(BlockManager)을 건드리지 않는다
- 외부 DNS · 위협 피드를 조회하지 않는다 (`AnalysisContract` 스냅샷만 쓴다)
- 운영 ``events`` 테이블에 쓰지 않는다 (격리된 ``replay_results`` 뿐)
- NIC 에 패킷을 주입하지 않는다 (저장된 특징값만 읽는다)

이 금지 목록은 주석이 아니라 **게이트 G0-11** 로 정적 검사한다. 주석은
약속이고 게이트는 사실이다.

실행 예산 (계획서): 동시 1개 · 10분 · 원본 256MB 상한. 초과하면 중단하고
사실을 남긴다 — 예산 초과를 숨기지 않는다.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from netwatcher.replay.analyzers import get_analyzer
from netwatcher.replay.contract import (
    REASON_BUDGET_EXCEEDED,
    REASON_FEATURE_MISSING,
    REASON_PAYLOAD_ENGINE,
    REASON_TRACE_INCOMPLETE,
    REASON_VERSION_MISMATCH,
    AnalysisContract,
    ReplayResult,
    unsupported_reason,
)
from netwatcher.replay.trace import Trace

logger = logging.getLogger("netwatcher.replay.service")

# 계획서 1장 검수·예산
MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_RUN_SECONDS = 600
MAX_CONCURRENT_RUNS = 1


class ReplayError(Exception):
    """리플레이 실행 오류."""


@dataclass
class BudgetReport:
    """예산 사용량. 초과하면 숨기지 않는다."""

    source_bytes: int = 0
    elapsed_seconds: float = 0.0
    max_source_bytes: int = MAX_SOURCE_BYTES
    max_seconds: int = MAX_RUN_SECONDS
    exceeded: bool = False
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_bytes": self.source_bytes,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "max_source_bytes": self.max_source_bytes,
            "max_seconds": self.max_seconds,
            "exceeded": self.exceeded,
            "reason": self.reason,
        }


@dataclass
class ReplayOutcome:
    """한 번의 실행 결과."""

    run_id: int
    status: str
    comparable: bool
    non_comparable_reasons: list[dict[str, Any]] = field(default_factory=list)
    results: dict[str, ReplayResult] = field(default_factory=dict)
    budget: BudgetReport = field(default_factory=BudgetReport)
    error: str | None = None

    def side_hash(self, side: str) -> str | None:
        combined = "".join(
            sorted(r.fingerprint() for r in self.results.values())
        )
        return combined or None


def _reason(code: str, detail: str) -> dict[str, Any]:
    return {"code": code, "detail": detail}


# ------------------------------------------------------------------
# 순수 실행 — DB도 네트워크도 없다
# ------------------------------------------------------------------

def execute_side(
    trace: Trace,
    contract: AnalysisContract,
    *,
    source_bytes: int = 0,
    max_source_bytes: int = MAX_SOURCE_BYTES,
) -> tuple[dict[str, ReplayResult], list[dict[str, Any]]]:
    """한 버전(한 계약)으로 trace 를 재실행한다.

    Returns:
        ``(엔진별 결과, 비교 불가 사유 목록)``

    순수 함수다 — I/O 가 없다. 그래서 결정성 테스트가 가능하다.
    """
    results: dict[str, ReplayResult] = {}
    reasons: list[dict[str, Any]] = []
    started = time.monotonic()

    if source_bytes > max_source_bytes:
        return {}, [_reason(
            REASON_BUDGET_EXCEEDED,
            f"입력 {source_bytes} B 가 상한 {max_source_bytes} B 를 넘었다",
        )]

    if not trace.complete:
        reasons.append(_reason(
            REASON_TRACE_INCOMPLETE,
            "입력이 잘렸다 — 같은 입력이 아니다",
        ))

    for engine in trace.engines:
        # 원본이 없는 payload 엔진을 먼저 본다.
        # "아직 지원 안 함" 과 "지원해도 원본이 없어 불가능" 은 다른 사실이다.
        # 계획서가 구분하라고 했으므로 더 구체적인 사유를 먼저 낸다.
        if engine in trace.payload_engines:
            results[engine] = ReplayResult(
                engine=engine, version=contract.build_version,
                unsupported=[REASON_PAYLOAD_ENGINE],
            )
            reasons.append(_reason(
                REASON_PAYLOAD_ENGINE,
                f"{engine} 은 원본이 없어 재현 불가 — 해시·요약으로 대신하지 않는다",
            ))
            continue

        why = unsupported_reason(engine)
        if why is not None:
            # 미지원은 실패가 아니라 명시적 미지원이다
            results[engine] = ReplayResult(
                engine=engine, version=contract.build_version,
                unsupported=[why],
            )
            reasons.append(_reason(why, f"{engine} 은(는) 재현 미지원"))
            continue

        analyzer = get_analyzer(engine)
        if analyzer is None:
            results[engine] = ReplayResult(
                engine=engine, version=contract.build_version,
                unsupported=[REASON_FEATURE_MISSING],
            )
            reasons.append(_reason(REASON_FEATURE_MISSING, f"{engine} 분석기 없음"))
            continue

        if not trace.records:
            results[engine] = ReplayResult(
                engine=engine, version=contract.build_version,
                unsupported=[REASON_FEATURE_MISSING],
            )
            reasons.append(_reason(REASON_FEATURE_MISSING, "기록된 특징값이 없다"))
            continue

        elapsed = time.monotonic() - started
        if elapsed > MAX_RUN_SECONDS:
            results[engine] = ReplayResult(
                engine=engine, version=contract.build_version,
                unsupported=[REASON_BUDGET_EXCEEDED],
            )
            reasons.append(_reason(REASON_BUDGET_EXCEEDED, "실행 시간 상한 초과"))
            continue

        observations = analyzer(trace.records, contract)
        results[engine] = ReplayResult(
            engine=engine,
            version=contract.build_version,
            observations=list(observations),
        )

    return results, reasons


# ------------------------------------------------------------------
# diff
# ------------------------------------------------------------------

def diff_sides(
    baseline: dict[str, ReplayResult],
    candidate: dict[str, ReplayResult],
    reasons: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """두 버전의 관측 차이를 낸다.

    비교할 수 없는 항목은 '없어짐' 이 아니라 **비교 불가** 로 보고한다.
    경보가 사라졌다고 줄어든 것이 아닐 수 있기 때문이다.
    """
    blocked = {r["code"] for r in reasons}

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged: list[str] = []

    baseline_map = {
        o.key(): o
        for r in baseline.values() for o in r.observations
    }
    candidate_map = {
        o.key(): o
        for r in candidate.values() for o in r.observations
    }

    for key, obs in candidate_map.items():
        if key not in baseline_map:
            added.append(obs.as_dict())
        elif baseline_map[key].as_dict() != obs.as_dict():
            changed.append({
                "key": key,
                "baseline": baseline_map[key].as_dict(),
                "candidate": obs.as_dict(),
            })
        else:
            unchanged.append(key)

    for key, obs in baseline_map.items():
        if key not in candidate_map:
            engine = obs.engine
            entry = (candidate.get(engine) or baseline.get(engine))
            unsupported = list(entry.unsupported) if entry else []
            if unsupported or engine in blocked:
                # 재현 불가로 사라진 것은 감소가 아니다
                removed.append({
                    **obs.as_dict(),
                    "removal_cause": unsupported or sorted(blocked),
                })
            else:
                removed.append(obs.as_dict())

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": sorted(unchanged),
        "counts": {
            "added": len(added), "removed": len(removed),
            "changed": len(changed), "unchanged": len(unchanged),
        },
        "non_comparable_reasons": list(reasons),
        "interpretation": {
            "notice": (
                "경보 감소는 오탐 감소의 증거가 아니다. 정상 여부는 담당자 확인이다."
            ),
        },
    }


def compare(
    trace: Trace,
    baseline_contract: AnalysisContract,
    candidate_contract: AnalysisContract,
    *,
    source_bytes: int = 0,
) -> ReplayOutcome:
    """같은 입력에 두 버전을 돌린다 (순수, 동기)."""
    reasons: list[dict[str, Any]] = []
    started = time.monotonic()

    baseline, b_reasons = execute_side(trace, baseline_contract, source_bytes=source_bytes)
    candidate, c_reasons = execute_side(trace, candidate_contract, source_bytes=source_bytes)
    reasons.extend(b_reasons)
    reasons.extend(c_reasons)

    # 버전 지문 자체가 다르면 '차이가 저 버전에서 왔는지' 알 수 없다
    if baseline_contract.versions() != candidate_contract.versions():
        differing = sorted(
            k for k, v in baseline_contract.versions().items()
            if v != candidate_contract.versions()[k]
        )
        reasons.append(_reason(
            REASON_VERSION_MISMATCH,
            f"버전 지문이 다름: {', '.join(differing)} — 차이의 출처를 특정할 수 없다",
        ))

    budget = BudgetReport(
        source_bytes=source_bytes,
        elapsed_seconds=time.monotonic() - started,
        exceeded=any(r["code"] == REASON_BUDGET_EXCEEDED for r in reasons),
    )

    return ReplayOutcome(
        run_id=0,
        status="completed",
        comparable=not reasons,
        non_comparable_reasons=reasons,
        results={**{f"baseline:{k}": v for k, v in baseline.items()},
                 **{f"candidate:{k}": v for k, v in candidate.items()}},
        budget=budget,
    )


def split_outcome(outcome: ReplayOutcome) -> tuple[dict[str, ReplayResult], dict[str, ReplayResult]]:
    """결합 결과를 양쪽으로 나눈다."""
    baseline = {k.split(":", 1)[1]: v for k, v in outcome.results.items() if k.startswith("baseline:")}
    candidate = {k.split(":", 1)[1]: v for k, v in outcome.results.items() if k.startswith("candidate:")}
    return baseline, candidate
