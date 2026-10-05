"""최소 대응 제안 API (계획서 4장, PR 14).

| 동작 | 최소 역할 | 이유 |
|-|-|-|
| 제안 생성 (POST /response-proposals) | analyst | 판단 입력이지만 결정은 아니다 |
| 영향 조회 (GET /response-proposals/{id}/impact) | viewer | 읽기 |

생성은 **제안만** 만든다. 승인은 하지 않는다. 여기서 201 로 응답해도
"적용됐다" 는 뜻이 아니다 — 그래서 응답에 `approved: false` 를 명시한다.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from netwatcher.observability.observation import (
    STATE_OBSERVED,
    STATE_PARTIAL,
    STATE_STALE,
    STATE_UNKNOWN,
)
from netwatcher.response.proposals import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    AssetMapping,
    MatchScope,
    ProposalError,
    build_proposal,
    impact_of,
)
from netwatcher.storage.repositories import ResponseProposalRepository
from netwatcher.web.rbac import Role, require_role

logger = logging.getLogger("netwatcher.web.routes.response_proposals")

VISH = [STATE_OBSERVED, STATE_PARTIAL, STATE_STALE, STATE_UNKNOWN]


class AssetInput(BaseModel):
    asset_id: str = Field(..., min_length=1, max_length=64)
    team: str = Field("unknown", max_length=64)
    criticality: str = Field("medium", pattern="^(low|medium|high|critical)$")
    confirmed: bool = False


class ProposalCreateRequest(BaseModel):
    source_ip: str = Field(..., min_length=1, max_length=64)
    engine: str = Field("", max_length=64)
    event_id: int | None = None
    visibility_state: str = Field(STATE_UNKNOWN)
    visibility_reasons: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(DEFAULT_TTL_SECONDS, ge=1, le=MAX_TTL_SECONDS)
    # 대상 매핑 — 확인 시각이 없으면 오래된 것으로 본다
    asset_id: str | None = Field(default=None, max_length=64)
    team: str = Field("unknown", max_length=64)
    criticality: str = Field("medium", pattern="^(low|medium|high|critical)$")
    protected: bool = False
    shared: bool = False
    confirmed_at: datetime | None = None
    # 지원 match 범위
    scope_kind: str = Field("ip", pattern="^(ip|port|asset)$")
    ports: list[int] = Field(default_factory=list, max_length=64)
    scope_asset_id: str | None = Field(default=None, max_length=64)
    service_aware: bool = False
    peers: list[AssetInput] = Field(default_factory=list, max_length=200)
    # AI 는 scope·TTL 을 결정하지 않는다
    created_by: str = Field("rules", max_length=32)


def create_response_proposals_router(repo: ResponseProposalRepository) -> APIRouter:
    """최소 대응 제안 라우터."""
    router = APIRouter(tags=["response-proposals"])

    @router.post("/response-proposals", status_code=201)
    async def create(req: ProposalCreateRequest,
                     _role: str = Depends(require_role(Role.ANALYST))) -> dict[str, Any]:
        """제안을 만든다. 적용하지 않는다."""
        if req.visibility_state not in VISH:
            raise HTTPException(status_code=400, detail="알 수 없는 가시성 상태")

        mapping = AssetMapping(
            ip=req.source_ip,
            asset_id=req.asset_id or "",
            team=req.team,
            criticality=req.criticality,
            protected=req.protected,
            shared=req.shared,
            confirmed_at=req.confirmed_at,
        ) if req.asset_id else None

        scope = MatchScope(
            kind=req.scope_kind,
            detail={
                **({"ports": req.ports} if req.ports else {}),
                **({"asset_id": req.scope_asset_id} if req.scope_asset_id else {}),
                **({"cidr": f"{req.source_ip}/32"} if req.scope_kind == "ip" else {}),
            },
            service_aware=req.service_aware,
        )

        try:
            proposal = build_proposal(
                source_ip=req.source_ip,
                visibility_state=req.visibility_state,
                visibility_reasons=req.visibility_reasons,
                mapping=mapping,
                scope=scope,
                peers=[p.model_dump() for p in req.peers],
                engine=req.engine,
                event_id=req.event_id,
                evidence=req.evidence,
                ttl_seconds=req.ttl_seconds,
                created_by=req.created_by,
            )
        except ProposalError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"message": str(exc), "context": exc.detail},
            ) from exc

        proposal_id = await repo.insert(proposal.as_row())
        return {
            "proposal_id": proposal_id,
            "status": "proposed",
            "approved": False,
            "notice": "이것은 제안이다. 승인 없이는 어떤 조치도 실행되지 않는다",
            "impact_url": f"/api/response-proposals/{proposal_id}/impact",
        }

    @router.get("/response-proposals")
    async def list_props(limit: int = 50,
                         _role: str = Depends(require_role(Role.VIEWER))) -> dict[str, Any]:
        return {"proposals": await repo.list_recent(min(limit, 200))}

    @router.get("/response-proposals/{proposal_id}/impact")
    async def impact(proposal_id: int,
                     _role: str = Depends(require_role(Role.VIEWER))) -> dict[str, Any]:
        """관측된 영향 범위와 **미확인 범위** 를 나누어 돌려준다."""
        row = await repo.get(proposal_id)
        if row is None:
            raise HTTPException(status_code=404, detail="제안을 찾을 수 없다")

        from netwatcher.response.proposals import ResponseProposal

        mapping_raw = row.get("target_mapping") or {}
        proposal = ResponseProposal(
            source_ip=row["source_ip"],
            ttl_seconds=row["ttl_seconds"],
            engine=row.get("engine") or "",
            event_id=row.get("event_id"),
            evidence=row.get("evidence") or {},
            visibility_state=row.get("visibility_state") or STATE_UNKNOWN,
            visibility_reasons=row.get("visibility_reasons") or [],
            target_mapping=(
                AssetMapping(
                    ip=mapping_raw.get("ip", ""),
                    asset_id=mapping_raw.get("asset_id", ""),
                    team=mapping_raw.get("team", "unknown"),
                    criticality=mapping_raw.get("criticality", "medium"),
                    protected=mapping_raw.get("protected", False),
                    shared=mapping_raw.get("shared", False),
                    confirmed_at=(
                        datetime.fromisoformat(mapping_raw["confirmed_at"])
                        if mapping_raw.get("confirmed_at") else None
                    ),
                ) if mapping_raw.get("asset_id") else None
            ),
            match_scope=(
                MatchScope(
                    kind=(row.get("match_scope") or {}).get("kind", "ip"),
                    detail={
                        k: v for k, v in (row.get("match_scope") or {}).items()
                        if k not in ("kind", "service_aware")
                    },
                    service_aware=(row.get("match_scope") or {}).get("service_aware", False),
                ) if row.get("match_scope") else None
            ),
            expected_assets=row.get("expected_assets") or [],
            unconfirmed_assets=row.get("unconfirmed_assets") or [],
            uncertainty=row.get("uncertainty") or {},
        )
        return {"proposal_id": proposal_id, "status": row["status"], **impact_of(proposal)}

    return router
