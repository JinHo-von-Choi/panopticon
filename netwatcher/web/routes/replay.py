"""리플레이 실행·비교 REST API (계획서 1장, PR 12).

| 동작 | 최소 역할 | 이유 |
|-|-|-|
| 실행 요청 (POST /replay-runs) | analyst | 비교를 "제안"하는 행위 |
| 조회 / diff (GET) | viewer | 읽기 |

주의 두 가지

1. **실행은 비동기다.** 핸들러는 시작만 하고 반환한다. 무거운 작업이
   요청 스레드를 붙잡으면 대시보드가 멈춘다.
2. **비교 불가 사유는 응답에 그대로 실린다.** 사유가 없는 비교는 만들지
   않는다. 실행 중이면 diff 를 내지 않는다.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from netwatcher.replay.contract import AnalysisContract
from netwatcher.replay.runs import ReplayRunService
from netwatcher.replay.trace import build_trace
from netwatcher.web.rbac import Role, require_role

logger = logging.getLogger("netwatcher.web.routes.replay")


class RecordInput(BaseModel):
    """기록된 특징값. 원본 패킷이 아니다."""

    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    dst_port: int | None = None
    bytes: int = 0
    ts: float = 0.0
    ip_proto: str | None = None


class ReplayRunRequest(BaseModel):
    records: list[RecordInput] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list, max_length=32)
    baseline_params: dict[str, Any] = Field(default_factory=dict)
    candidate_params: dict[str, Any] = Field(default_factory=dict)
    baseline_version: str = Field(..., min_length=1, max_length=128)
    candidate_version: str = Field(..., min_length=1, max_length=128)
    config_version: str = Field("unknown", max_length=64)
    feed_version: str = Field("unknown", max_length=64)
    whitelist_version: str = Field("unknown", max_length=64)
    normalizer_version: str = Field("unknown", max_length=64)
    complete: bool = True
    tick_seconds: int = Field(1, ge=1, le=3600)
    warmup_seconds: int = Field(0, ge=0, le=86400)
    reason: str = Field("", max_length=500)


def create_replay_router(service: ReplayRunService) -> APIRouter:
    """리플레이 라우터를 만든다."""
    router = APIRouter(tags=["replay"])

    @router.post("/replay-runs", status_code=202)
    async def create_run(
        req: ReplayRunRequest,
        _role: str = Depends(require_role(Role.ANALYST)),
    ) -> dict[str, Any]:
        """리플레이 실행을 요청한다. 즉시 반환하고 백그라운드에서 돈다."""
        if not req.engines:
            raise HTTPException(status_code=400, detail="engines 가 비었다")

        trace = build_trace(
            [r.model_dump() for r in req.records],
            req.engines,
            complete=req.complete,
            tick_seconds=req.tick_seconds,
            warmup_seconds=req.warmup_seconds,
        )

        def _contract(version: str, params: dict) -> AnalysisContract:
            return AnalysisContract(
                build_version=version,
                config_version=req.config_version,
                feed_version=req.feed_version,
                whitelist_version=req.whitelist_version,
                normalizer_version=req.normalizer_version,
                engine_params=params,
            )

        run_id = await service.submit(
            trace,
            _contract(req.baseline_version, req.baseline_params),
            _contract(req.candidate_version, req.candidate_params),
        )
        return {
            "run_id": run_id,
            "status": "pending",
            "trace_id": trace.trace_id,
            "input_count": trace.input_count,
            "input_hash": trace.input_hash(),
            "note": "실행은 비동기다. GET /replay-runs/{id} 로 진행을 확인한다",
        }

    @router.get("/replay-runs")
    async def list_runs(
        limit: int = 50,
        _role: str = Depends(require_role(Role.VIEWER)),
    ) -> dict[str, Any]:
        rows = await service.list_runs(limit=min(limit, 200))
        return {"runs": rows}

    @router.get("/replay-runs/{run_id}")
    async def get_run(
        run_id: int,
        _role: str = Depends(require_role(Role.VIEWER)),
    ) -> dict[str, Any]:
        run = await service.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="리플레이 실행을 찾을 수 없다")
        return {"run": run}

    @router.get("/replay-runs/{run_id}/diff")
    async def get_diff(
        run_id: int,
        _role: str = Depends(require_role(Role.VIEWER)),
    ) -> dict[str, Any]:
        """두 버전의 관측 차이.

        완료되지 않은 실행에는 diff 를 내지 않는다. 완료되었더라도 비교
        불가 사유가 있으면 그 사유를 함께 실린다.
        """
        payload = await service.get_diff(run_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="리플레이 실행을 찾을 수 없다")
        return payload

    return router
