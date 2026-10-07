"""비동기 리플레이 실행 오케스트레이션 (계획서 1장).

    "API 는 POST /replay-runs, GET /replay-runs/{id}/diff 로 나누고
     실행은 비동기 작업으로 제한한다."

그래서 HTTP 핸들러는 **실행을 시작하기만** 하고 끝낸다. 무거운 작업은
백그라운드에서 돌아가고, 상태는 `replay_runs.status` 로 남는다.
동시 실행은 1개로 제한한다 (계획서: 동시 1개).
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
from pathlib import Path
import logging
from typing import Any

from netwatcher.replay.contract import AnalysisContract
from netwatcher.replay.service import (
    MAX_CONCURRENT_RUNS,
    diff_sides,
    split_outcome,
)
from netwatcher.replay.runner import ReplayRunner, ReplayBudgetError
from netwatcher.replay.trace import Trace
from netwatcher.storage.repositories import ReplayRepository

logger = logging.getLogger("netwatcher.replay.runs")

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_ABORTED = "aborted"


class ReplayAdmissionError(RuntimeError):
    def __init__(self, reason, status_code=429):
        super().__init__(reason)
        self.status_code = status_code


class ReplayRunService:
    """리플레이 실행을 큐로 돌리고 결과를 격리 저장한다."""

    def __init__(self, repository: ReplayRepository, *, max_pending_runs=2,
                 max_pending_bytes=32 * 1024 * 1024, timeout=600) -> None:
        self._repo = repository
        digest = hashlib.sha256()
        for filename in ('analyzers.py', 'contract.py', 'service.py', 'trace.py', 'runner.py'):
            digest.update(filename.encode())
            digest.update((Path(__file__).parent / filename).read_bytes())
        self.implementation_version = digest.hexdigest()
        # 동시 1개 (계획서 예산). 넘으면 대기한다 — 중복 실행하지 않는다.
        self._gate = asyncio.Semaphore(MAX_CONCURRENT_RUNS)
        self._max_queue_age = 300
        self._tasks: dict[int, asyncio.Task] = {}
        self._max_pending_runs = max(1, int(max_pending_runs))
        self._max_pending_bytes = max(1024, int(max_pending_bytes))
        self._pending_runs = 0
        self._pending_bytes = 0
        self._admission = asyncio.Lock()
        self._runner = ReplayRunner(timeout=timeout)
        self._stopping = False

    def status(self):
        return {'pending_runs': self._pending_runs, 'pending_bytes': self._pending_bytes,
                'max_pending_runs': self._max_pending_runs, 'max_pending_bytes': self._max_pending_bytes}

    def stop_accepting(self):
        self._stopping = True
        self._runner.terminate_now()

    async def stop(self):
        self.stop_accepting()
        tasks = tuple(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            pending_ids = tuple(self._tasks)
            await asyncio.gather(*tasks, return_exceptions=True)
            for run_id in pending_ids:
                try:
                    async with asyncio.timeout(.1):
                        await self._repo.finish_run(run_id, STATUS_ABORTED, baseline_hash=None,
                            candidate_hash=None, reasons=[{'code': 'budget_exceeded', 'detail': 'shutdown'}],
                            comparable=False, budget={'exceeded': True, 'reason': 'shutdown'})
                except Exception:
                    logger.warning('Replay shutdown state unconfirmed: run=%s', run_id)

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
        trace = await self._repo.get_trace(run['trace_id'])
        if trace:
            payload['input_hash'] = trace['input_hash']
            payload['comparison_context'] = trace.get('compat_snapshot') or {}

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
        payload["diff"] = await asyncio.to_thread(diff_sides,
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
        trace, baseline, candidate = copy.deepcopy((trace, baseline, candidate))
        size = trace.size_bytes
        async with self._admission:
            if self._stopping:
                raise ReplayAdmissionError('Replay service is stopping', 503)
            if size > self._max_pending_bytes:
                raise ReplayAdmissionError('Replay source exceeds the memory admission budget', 413)
            if (self._pending_runs >= self._max_pending_runs or
                    self._pending_bytes + size > self._max_pending_bytes):
                raise ReplayAdmissionError('Replay queue budget exceeded')
            self._pending_runs += 1
            self._pending_bytes += size
        try:
            trace.compat_snapshot['implementation_version'] = self.implementation_version
            trace.compat_snapshot['baseline_contract'] = {
                'versions': baseline.versions(), 'params': baseline.engine_params}
            trace.compat_snapshot['candidate_contract'] = {
                'versions': candidate.versions(), 'params': candidate.engine_params}
            await self._repo.insert_trace(trace.as_row())
            run_id = await self._repo.create_run(
                trace.trace_id, baseline.build_version, candidate.build_version,
            )
            if self._stopping:
                await self._repo.finish_run(run_id, STATUS_ABORTED, baseline_hash=None,
                    candidate_hash=None, reasons=[{'code': 'budget_exceeded', 'detail': 'shutdown'}],
                    comparable=False, budget={'exceeded': True, 'reason': 'shutdown'})
                raise ReplayAdmissionError('Replay service is stopping', 503)
            task = asyncio.create_task(self._owned_run(run_id, trace, baseline, candidate, size))
            self._tasks[run_id] = task
            def release(finished):
                self._tasks.pop(run_id, None)
                self._pending_runs -= 1
                self._pending_bytes -= size
                if not finished.cancelled() and finished.exception() is not None:
                    logger.error('Replay result persistence failed: run=%s error=%s',
                                 run_id, type(finished.exception()).__name__)
            task.add_done_callback(release)
            return run_id
        except BaseException:
            self._pending_runs -= 1
            self._pending_bytes -= size
            raise

    async def _owned_run(self, run_id, trace, baseline, candidate, size):
        try:
            await self._run(run_id, trace, baseline, candidate, size)
        except asyncio.CancelledError:
            try:
                async with asyncio.timeout(.25):
                    await self._repo.finish_run(run_id, STATUS_ABORTED, baseline_hash=None,
                        candidate_hash=None, reasons=[{'code': 'budget_exceeded', 'detail': 'shutdown'}],
                        comparable=False, budget={'exceeded': True, 'reason': 'shutdown'})
            except Exception:
                logger.warning('Replay cancellation persistence unconfirmed: run=%s', run_id)
            raise

    async def _run(
        self, run_id: int, trace: Trace,
        baseline: AnalysisContract, candidate: AnalysisContract,
        size: int,
    ) -> None:
        try:
            await asyncio.wait_for(self._gate.acquire(), self._max_queue_age)
        except asyncio.TimeoutError:
            await self._repo.finish_run(run_id, STATUS_ABORTED, baseline_hash=None,
                candidate_hash=None, reasons=[{'code': 'budget_exceeded', 'detail': 'queue_age'}],
                comparable=False, budget={'exceeded': True, 'reason': 'queue_age'})
            return
        try:
            await self._repo.mark_running(run_id)
            try:
                outcome = await self._runner.run(trace, baseline, candidate, size)
            except ReplayBudgetError as error:
                await self._repo.finish_run(run_id, STATUS_ABORTED, baseline_hash=None,
                    candidate_hash=None, reasons=[{'code': 'budget_exceeded', 'detail': str(error)}],
                    comparable=False, budget={'exceeded': True, 'reason': str(error)})
                return
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

        finally:
            self._gate.release()

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
