"""비동기 리플레이 실행 오케스트레이션 (계획서 1장).

    "API 는 POST /replay-runs, GET /replay-runs/{id}/diff 로 나누고
     실행은 비동기 작업으로 제한한다."

그래서 HTTP 핸들러는 **실행을 시작하기만** 하고 끝낸다. 무거운 작업은
백그라운드에서 돌아가고, 상태는 `replay_runs.status` 로 남는다.
동시 실행은 1개로 제한한다 (계획서: 동시 1개).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from netwatcher.replay.contract import AnalysisContract
from netwatcher.replay.service import (
    MAX_CONCURRENT_RUNS,
    compare,
    diff_sides,
    split_outcome,
)
from netwatcher.replay.trace import Trace
from netwatcher.storage.repositories import ReplayRepository

logger = logging.getLogger("netwatcher.replay.runs")

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_ABORTED = "aborted"


class ReplayRunService:
    """리플레이 실행을 큐로 돌리고 결과를 격리 저장한다."""

    def __init__(self, repository: ReplayRepository) -> None:
        self._repo = repository
        # 동시 1개 (계획서 예산). 넘으면 대기한다 — 중복 실행하지 않는다.
        self._gate = asyncio.Semaphore(MAX_CONCURRENT_RUNS)
        self._tasks: dict[int, asyncio.Task] = {}

    # ------------------------------------------------------------------
    # 조회
    # ------------------------------------------------------------------

    async def get_run(self, run_id: int) -> dict | None:
        return await self._repo.get_run(run_id)

    async def list_runs(self, limit: int = 50) -> list[dict]:
        return await self._repo.list_runs(limit)

    async def get_diff(self, run_id: int) -> dict[str, Any] | None:
        """실행이 끝난 뒤에만 diff 를 낸다.

        끝나지 않았으면 없는 것으로 답한다. 진행 중 결과를 비교하면
        "비교했다" 고 말할 수 없다.
        """
        run = await self._repo.get_run(run_id)
        if run is None:
            return None

        payload: dict[str, Any] = {
            "run_id": run_id,
            "status": run["status"],
            "trace_id": run["trace_id"],
            "baseline_version": run["baseline_version"],
            "candidate_version": run["candidate_version"],
            "comparable": run["comparable"],
            "non_comparable_reasons": run["non_comparable_reasons"],
            "budget": run.get("budget_detail") or {},
        }

        if run["status"] != STATUS_COMPLETED:
            payload["diff"] = None
            payload["note"] = "실행이 완료되지 않아 비교하지 않는다"
            return payload

        rows = await self._repo.list_results(run_id)
        baseline_rows = [r for r in rows if r["side"] == "baseline"]
        candidate_rows = [r for r in rows if r["side"] == "candidate"]

        payload["baseline_result_hash"] = run["baseline_result_hash"]
        payload["candidate_result_hash"] = run["candidate_result_hash"]
        payload["results_identical"] = (
            run["baseline_result_hash"] is not None
            and run["baseline_result_hash"] == run["candidate_result_hash"]
        )
        payload["baseline"] = [self._result_view(r) for r in baseline_rows]
        payload["candidate"] = [self._result_view(r) for r in candidate_rows]
        payload["diff"] = diff_sides(
            _rows_to_results(baseline_rows),
            _rows_to_results(candidate_rows),
            reasons=run["non_comparable_reasons"] or [],
        )
        return payload

    @staticmethod
    def _result_view(row: dict) -> dict[str, Any]:
        return {
            "engine": row["engine"],
            "result_hash": row["result_hash"],
            "observation_count": row["observation_count"],
            "unsupported": row["unsupported"],
        }

    # ------------------------------------------------------------------
    # 실행
    # ------------------------------------------------------------------

    async def submit(
        self,
        trace: Trace,
        baseline: AnalysisContract,
        candidate: AnalysisContract,
    ) -> int:
        """실행을 큐에 올리고 run id 를 반환한다 (즉시 반환)."""
        await self._repo.insert_trace(trace.as_row())
        run_id = await self._repo.create_run(
            trace.trace_id, baseline.build_version, candidate.build_version,
        )
        task = asyncio.create_task(self._run(run_id, trace, baseline, candidate))
        self._tasks[run_id] = task
        return run_id

    async def _run(
        self, run_id: int, trace: Trace,
        baseline: AnalysisContract, candidate: AnalysisContract,
    ) -> None:
        async with self._gate:
            await self._repo.mark_running(run_id)
            try:
                outcome = compare(
                    trace, baseline, candidate, source_bytes=trace.size_bytes,
                )
            except Exception as exc:  # 실행 실패도 사실이므로 남긴다
                logger.exception("리플레이 실행 실패 (run=%s)", run_id)
                await self._repo.finish_run(
                    run_id, STATUS_FAILED, baseline_hash=None, candidate_hash=None,
                    reasons=[], comparable=False, budget={},
                    error=f"{type(exc).__name__}: {exc}",
                )
                return

            base_results, cand_results = split_outcome(outcome)
            for side, results in (("baseline", base_results), ("candidate", cand_results)):
                for engine, result in results.items():
                    await self._repo.insert_result(
                        run_id, side, engine, result.fingerprint(),
                        [o.as_dict() for o in result.observations],
                        list(result.unsupported),
                    )

            status = STATUS_COMPLETED
            if outcome.budget.exceeded:
                status = STATUS_ABORTED
            await self._repo.finish_run(
                run_id, status,
                baseline_hash=_side_hash(base_results),
                candidate_hash=_side_hash(cand_results),
                reasons=outcome.non_comparable_reasons,
                comparable=outcome.comparable,
                budget=outcome.budget.as_dict(),
            )

    async def wait(self, run_id: int, timeout: float = 30.0) -> None:
        """테스트·대기용. HTTP 경로에서는 호출하지 않는다."""
        task = self._tasks.get(run_id)
        if task is not None:
            await asyncio.wait_for(task, timeout=timeout)


def _side_hash(results: dict) -> str | None:
    combined = "".join(sorted(r.fingerprint() for r in results.values()))
    return combined or None


def _rows_to_results(rows: list[dict]) -> dict:
    from netwatcher.replay.contract import Observation, ReplayResult

    out: dict[str, ReplayResult] = {}
    for row in rows:
        observations = [
            Observation(
                engine=o.get("engine", row["engine"]),
                kind=o.get("kind", ""),
                subject=o.get("subject", ""),
                features=o.get("features", {}),
                observed_at=o.get("observed_at", 0.0),
                seq=o.get("seq", 0),
            )
            for o in (row.get("observations") or [])
        ]
        out[row["engine"]] = ReplayResult(
            engine=row["engine"],
            version="",
            observations=observations,
            unsupported=list(row.get("unsupported") or []),
        )
    return out
