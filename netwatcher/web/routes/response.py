"""ResponseAction REST API (계획서 2장, PR 13).

    "POST /change-proposals/{id}/approve 와 /activate 는 분리하고 승인의 해시·
     기준 버전과 다르면 409 로 거부한다."

왜 분리인가

| 단계 | 뜻 | 실패해도 남는 것 |
|-|-|-|
| approve | 사람이 결정했다 | 결정 + TTL + 대상 |
| activate | OS 에 넣었다 | 적용 의도 + 상태 |

합쳐 두면 "승인만 되고 적용은 안 된 상태" 를 표현할 수 없다. 분리해야 그
상태가 **존재하는 상태** 로 남는다.

이 라우터는 방화벽 권한이 없다. `executor` 인터페이스만 호출하고, 그
인터페이스는 대상·방향·TTL 만 받는다.
"""

from __future__ import annotations

import logging
from typing import Any

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from netwatcher.response.executor import Executor, executor_capabilities
from netwatcher.response.proposals import MAPPING_STALE_SECONDS
from netwatcher.response.lifecycle import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    STATE_APPLYING,
    STATE_REQUESTED,
    STATE_UNKNOWN,
    Approval,
    LifecycleError,
    RateLimiter,
    assert_mapping_fresh,
    candidate_hash,
    is_protected,
    new_idempotency_key,
    require_transition,
    set_expire_once,
)
from netwatcher.storage.repositories import ResponseActionRepository
from netwatcher.web.rbac import Role, require_role

logger = logging.getLogger("netwatcher.web.routes.response")


class ApproveRequest(BaseModel):
    """승인 시점에 고정되는 것."""

    target: str = Field(..., min_length=1, max_length=64)
    direction: str = Field("input", pattern="^(input|output|forward)$")
    ttl_seconds: int = Field(DEFAULT_TTL_SECONDS, ge=1, le=MAX_TTL_SECONDS)
    scope: dict[str, Any] = Field(default_factory=dict)
    base_version: str = Field("unknown", max_length=64)
    # 대상 매핑을 마지막으로 확인한 시각. 실행 시점 신선도 검사의 근거
    mapping_confirmed_at: datetime | None = None


class ActivateRequest(BaseModel):
    """적용 시점의 값. 승인 때와 다르면 409."""

    target: str = Field(..., min_length=1, max_length=64)
    direction: str = Field("input", pattern="^(input|output|forward)$")
    ttl_seconds: int = Field(DEFAULT_TTL_SECONDS, ge=1, le=MAX_TTL_SECONDS)
    scope: dict[str, Any] = Field(default_factory=dict)
    base_version: str = Field("unknown", max_length=64)


def _http(exc: LifecycleError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code, detail={"message": str(exc), **({"context": exc.detail} if exc.detail else {})},
    )


def create_response_router(
    repository: ResponseActionRepository,
    executor: Executor,
) -> APIRouter:
    """조치 생애주기 라우터."""
    router = APIRouter(tags=["response"])

    # 적용 횟수 제한 (계획서 2장 초기 제한: 동시 3개 · 분당 1개).
    # 라우터 인스턴스 단위라 프로세스 안에서만 유효하다. 여러 프로세스로
    # 같은 장비를 다룰 때는 Redis 기반 제한으로 바꿔야 한다.
    limiter = RateLimiter()

    @router.get("/response/capabilities")
    async def capabilities(_role: str = Depends(require_role(Role.VIEWER))) -> dict[str, Any]:
        """이 배포가 실제로 무엇을 할 수 있는지.

        "차단이 적용된다" 고 말할 근거가 되는 값이다. 여기서 `applies_to_os`
        가 false 면 대시보드는 적용 완료를 success 로 칠하면 안 된다.
        """
        return executor_capabilities(executor.name, executor)

    @router.post("/change-proposals/{proposal_id}/approve", status_code=201)
    async def approve(
        proposal_id: int,
        req: ApproveRequest,
        _role: dict = Depends(require_role(Role.ADMIN)),
    ) -> dict[str, Any]:
        """승인 — 사람이 결정했다는 기록만 남긴다. OS 를 건드리지 않는다."""
        if is_protected(req.target):
            raise HTTPException(
                status_code=409,
                detail={"message": "보호 대상은 자동 조치 대상이 아니다", "target": req.target},
            )

        from datetime import timezone

        approval = Approval(
            approved_hash=candidate_hash(
                req.target, req.direction, req.ttl_seconds, req.scope),
            base_version=req.base_version,
            approved_by=str(_role.get("uid") or _role["sub"]),
            approved_at=datetime.now(timezone.utc),
            target=req.target,
            direction=req.direction,
            ttl_seconds=req.ttl_seconds,
        )
        action_id = await repository.create_requested(
            proposal_id=proposal_id,
            approval=approval,
            idempotency_key=new_idempotency_key(),
            mapping_confirmed_at=req.mapping_confirmed_at,
        )
        return {
            "action_id": action_id,
            "state": STATE_REQUESTED,
            "approval": approval.as_dict(),
            "note": "승인은 결정 기록이다. 적용은 /response-actions/{id}/activate 다",
        }

    @router.post("/response-actions/{action_id}/activate")
    async def activate(
        action_id: int,
        req: ActivateRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        _role: str = Depends(require_role(Role.ADMIN)),
    ) -> dict[str, Any]:
        """적용 — 승인된 것과 다르면 409 로 거부한다.

        중복 요청은 첫 expire_at 을 그대로 재사용한다. 재시도가 만료를
        늘리면 실제 노출 시간이 계획보다 길어진다.
        """
        action = await repository.get(action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="조치 레코드를 찾을 수 없다")

        key = idempotency_key or action.get("idempotency_key") or new_idempotency_key()

        # 이미 같은 키로 실행된 적이 있으면 그 결과를 돌려준다
        existing = await repository.find_by_idempotency_key(key)
        if existing is not None and int(existing["id"]) != action_id:
            raise HTTPException(
                status_code=409,
                detail={"message": "idempotency key 가 다른 조치에 이미 사용되었다",
                        "existing_action_id": int(existing["id"])},
            )

        try:
            require_transition(action["state"], STATE_APPLYING)
        except LifecycleError as exc:
            raise _http(exc) from exc

        from netwatcher.response.executor import ExecutionRequest

        try:
            request = ExecutionRequest(
                target=req.target, direction=req.direction,
                ttl_seconds=req.ttl_seconds, rule_tag=f"nw-{action_id}",
                scope=req.scope,
            )
            # 승인된 해시·기준 버전과 대조 — 다르면 여기서 409
            approval_hash = action.get("approved_hash")
            if approval_hash != request.content_hash() or (
                action.get("base_version") != req.base_version
            ):
                raise LifecycleError(
                    "승인된 해시 또는 기준 버전과 다릅니다 — 재승인이 필요합니다",
                    status_code=409,
                    detail={
                        "approved_hash": approval_hash,
                        "current_hash": request.content_hash(),
                        "approved_base_version": action.get("base_version"),
                        "requested_base_version": req.base_version,
                    },
                )

            # 매핑이 오래됐으면 실행하지 않는다 — 제안은 됐어도 실행은 안 된다
            assert_mapping_fresh(
                action.get("mapping_confirmed_at") or
                (action.get("target_mapping") or {}).get("confirmed_at"),
                max_age_seconds=MAPPING_STALE_SECONDS,
            )

            # 속도 제한은 위 검사들을 통과한 뒤에 건다. 409 로 거절된 요청은
            # OS 를 건드리지 않았으므로 상한을 소모하지 않는다.
            try:
                limiter.acquire(action_id)
            except LifecycleError as exc:
                # 거절이므로 실행 기록을 남기지 않는다. 실행하지 않은 것을
                # 미확인 실행으로 기록하면 확인 필요 없는 조치가 쌓인다.
                raise _http(exc) from exc

            await repository.mark_applying(action_id, idempotency_key=key)
            result = executor.apply(request)
        except LifecycleError as exc:
            await repository.mark_unknown(action_id, str(exc))
            raise _http(exc) from exc
        finally:
            limiter.release(action_id)

        expire_at = set_expire_once(action.get("expire_at"), req.ttl_seconds)
        state = (
            "active_verified" if result.verified
            else STATE_UNKNOWN if result.observed == "unknown"
            else result.outcome
        )
        await repository.finish(
            action_id, state=state, expire_at=expire_at,
            rule_fingerprint=result.rule_fingerprint,
            rule_tag=f"nw-{action_id}", error=result.detail or None,
        )
        await repository.add_receipt(
            action_id, phase="apply", outcome=result.outcome, detail=result.as_dict(),
        )
        return {
            "action_id": action_id,
            "state": state,
            "verified": result.verified,
            "expire_at": expire_at.isoformat() if expire_at else None,
            "result": result.as_dict(),
            "notice": (
                "shadow 모드에서는 OS 변경이 없다. 'active' 가 아니어도 실패가 아니다"
                if not result.verified else "적용을 조회로 확인했다"
            ),
        }

    @router.get("/response-actions/{action_id}")
    async def get_action(
        action_id: int,
        _role: str = Depends(require_role(Role.VIEWER)),
    ) -> dict[str, Any]:
        action = await repository.get(action_id)
        if action is None:
            raise HTTPException(status_code=404, detail="조치 레코드를 찾을 수 없다")
        receipts = await repository.list_receipts(action_id)
        return {"action": action, "receipts": receipts}

    @router.get("/response-actions")
    async def list_actions(
        limit: int = 50,
        _role: str = Depends(require_role(Role.VIEWER)),
    ) -> dict[str, Any]:
        return {"actions": await repository.list_recent(min(limit, 200))}

    return router
