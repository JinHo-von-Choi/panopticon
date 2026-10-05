"""최소 대응 제안과 영향 범위 (계획서 4장, PR 14).

    "ResponseProposal 은 근거·가시성 상태·대상 매핑·지원 match 범위·예상 관련
     자산·불확실성·TTL 을 묶는다."
    "POST /response-proposals 는 제안만 만들고 /impact 는 관측된 영향 범위와
     미확인 범위를 돌려준다."
    "규칙 기반 제안기만 사용하며 AI 는 승인·scope·TTL 을 결정하지 않는다."

이 모듈이 지키는 것

1. **넓은 IP 차단으로 자동 대체하지 않는다.** 범위를 좁히지 못했으면
   제안하지 않는다. 좁히는 방법이 없는 것보다 넓게 막는 것이 나쁘다.
2. **확정된 영향과 미확인 범위를 분리한다.** 공유 IP·NAT·DHCP 때문에
   "누가Communication 하는지" 확인되지 않을 수 있다. 그것을 확정으로
   묶으면 사람이 "업무 영향이 없다" 고 오독한다.
3. **응답이 늦으면 캐시된 매핑으로 실행하지 않는다.** 매핑이 오래됐다는
   사실 자체가 사유다.
4. **관측이 온전하지 않으면 신규 조치를 제안하지 않는다.** (계획서 3장:
   stale/unknown 은 신규 조치 금지 조건)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from netwatcher.observability.observation import (
    STATE_PARTIAL,
    STATE_STALE,
    STATE_UNKNOWN,
)

logger = logging.getLogger("netwatcher.response.proposals")

MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 300

# 매핑이 이보다 오래됐으면 "확인되지 않은" 것으로 본다
MAPPING_STALE_SECONDS = 900  # 15분

# 좁힐 수 없는 상황 — 넓은 IP 차단으로 대체하지 않는다
UNCERTAINTY_SHARED_IP = "shared_ip_or_nat"
UNCERTAINTY_STALE_MAPPING = "asset_mapping_stale"
UNCERTAINTY_DHCP = "dynamic_address_possible"
UNCERTAINTY_NO_PRECISION = "backend_cannot_narrow_scope"
UNCERTAINTY_VISIBILITY = "observation_not_trustworthy"


class ProposalError(Exception):
    """제안 생성 불가."""

    def __init__(self, message: str, status_code: int = 400, detail: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


# ------------------------------------------------------------------
# 자산 매핑
# ------------------------------------------------------------------

@dataclass(frozen=True)
class AssetMapping:
    """주소 → 자산. 안정 ID 를 함께 가진다."""

    ip: str
    asset_id: str
    team: str = "unknown"
    criticality: str = "medium"
    protected: bool = False
    # 이 매핑이 언제 확인됐는지
    confirmed_at: datetime | None = None
    # 하나의 주소가 여러 자산으로 보이는가 (공유 IP · NAT)
    shared: bool = False

    def age_seconds(self, now: datetime | None = None) -> float | None:
        if self.confirmed_at is None:
            return None
        base = now or datetime.now(timezone.utc)
        return (base - self.confirmed_at).total_seconds()

    def is_stale(self, now: datetime | None = None) -> bool:
        age = self.age_seconds(now)
        return age is None or age > MAPPING_STALE_SECONDS

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "asset_id": self.asset_id,
            "team": self.team,
            "criticality": self.criticality,
            "protected": self.protected,
            "shared": self.shared,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
        }


@dataclass
class MatchScope:
    """백엔드가 실제로 좁힐 수 있는 범위."""

    # 예: {"kind": "port", "ports": [22, 80]} / {"kind": "ip", "cidr": "8.8.8.8/32"}
    kind: str
    detail: dict[str, Any] = field(default_factory=dict)
    # 이 백엔드가 서비스 단위 제한을 지원하는가
    service_aware: bool = False

    def is_precise(self) -> bool:
        # bool 로 감싸지 않으면 값이 없을 때 None 이 나간다.
        # 판정 함수가 None 을 돌려주는 것은 호출부가 if 로 삼키는 순간 드러난다.
        return bool(
            self.kind in ("port", "asset")
            and (self.detail.get("ports") or self.detail.get("asset_id"))
        )

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, **self.detail, "service_aware": self.service_aware}


# ------------------------------------------------------------------
# 제안
# ------------------------------------------------------------------

@dataclass
class ResponseProposal:
    """제안 본체. 이 모듈은 승인하지 않는다."""

    source_ip: str
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    engine: str = ""
    event_id: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    visibility_state: str = STATE_UNKNOWN
    visibility_reasons: list[str] = field(default_factory=list)
    target_mapping: AssetMapping | None = None
    match_scope: MatchScope | None = None
    expected_assets: list[dict[str, Any]] = field(default_factory=list)
    unconfirmed_assets: list[dict[str, Any]] = field(default_factory=list)
    uncertainty: dict[str, Any] = field(default_factory=dict)
    created_by: str = "rules"

    def as_row(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "engine": self.engine,
            "source_ip": self.source_ip,
            "evidence": dict(self.evidence),
            "visibility_state": self.visibility_state,
            "visibility_reasons": list(self.visibility_reasons),
            "target_mapping": (
                self.target_mapping.as_dict() if self.target_mapping else {}
            ),
            "match_scope": self.match_scope.as_dict() if self.match_scope else {},
            "expected_assets": list(self.expected_assets),
            "unconfirmed_assets": list(self.unconfirmed_assets),
            "uncertainty": dict(self.uncertainty),
            "ttl_seconds": self.ttl_seconds,
            "created_by": self.created_by,
        }


# ------------------------------------------------------------------
# 제안기 (규칙 기반만)
# ------------------------------------------------------------------

def build_proposal(
    *,
    source_ip: str,
    visibility_state: str,
    visibility_reasons: list[str],
    mapping: AssetMapping | None,
    scope: MatchScope | None,
    peers: list[dict[str, Any]],
    engine: str = "",
    event_id: int | None = None,
    evidence: dict[str, Any] | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: datetime | None = None,
    created_by: str = "rules",
) -> ResponseProposal:
    """규칙 기반으로 제안을 만든다.

    Raises:
        ProposalError: 관측이 신뢰할 수 없거나, 범위를 좁힐 수 없거나,
            매핑이 확인되지 않은 경우. **넓은 IP 차단으로 대체하지 않는다.**
    """
    if created_by != "rules":
        # AI 는 승인·scope·TTL 을 결정하지 않는다 (계획서 4장)
        raise ProposalError(
            "제안 생성은 규칙 기반만 허용한다", status_code=403,
            detail={"created_by": created_by},
        )

    if visibility_state in (STATE_STALE, STATE_UNKNOWN):
        # 자동 조치 검토 단계에서 stale/unknown 은 신규 조치 금지 조건
        raise ProposalError(
            "관측 상태가 신뢰할 수 없어 제안을 만들지 않는다", status_code=409,
            detail={"visibility_state": visibility_state, "reasons": visibility_reasons},
        )

    uncertainty: dict[str, Any] = {}
    reasons: list[str] = []

    if mapping is None:
        raise ProposalError(
            "대상 매핑이 없다 — 주소가 누구인지 확인되지 않았다", status_code=409,
            detail={"source_ip": source_ip},
        )
    if mapping.shared:
        uncertainty[UNCERTAINTY_SHARED_IP] = (
            "하나의 주소가 여러 자산으로 보인다 — 공유 IP 또는 NAT"
        )
        reasons.append(UNCERTAINTY_SHARED_IP)
    if mapping.is_stale(now):
        # 응답이 늦으면 캐시된 매핑으로 실행하지 않는다
        uncertainty[UNCERTAINTY_STALE_MAPPING] = (
            f"매핑 확인 시각이 {MAPPING_STALE_SECONDS}초 초과 경과"
        )
        reasons.append(UNCERTAINTY_STALE_MAPPING)
    if mapping.protected:
        uncertainty["protected_target"] = "보호 자산"

    if scope is None or not scope.is_precise():
        # 좁힐 수 없으면 넓은 IP 차단으로 대체하지 않는다 — 제안하지 않는다
        uncertainty[UNCERTAINTY_NO_PRECISION] = (
            "백엔드가 이 범위를 좁힐 수 없다 — 넓은 차단으로 대체하지 않는다"
        )
        raise ProposalError(
            "범위를 좁힐 수 없어 제안을 만들지 않는다", status_code=409,
            detail={"uncertainty": uncertainty, "reasons": reasons},
        )

    if visibility_state == STATE_PARTIAL:
        uncertainty[UNCERTAINTY_VISIBILITY] = "관측 창이 온전하지 않다"
        reasons.append(UNCERTAINTY_VISIBILITY)

    if not 0 < ttl_seconds <= MAX_TTL_SECONDS:
        raise ProposalError("TTL 은 0 초과 상한 이하여야 한다")

    # 확정된 자산과 미확인 자산을 분리한다
    confirmed = [p for p in peers if p.get("confirmed")]
    unconfirmed = [p for p in peers if not p.get("confirmed")]

    return ResponseProposal(
        source_ip=source_ip,
        ttl_seconds=ttl_seconds,
        engine=engine,
        event_id=event_id,
        evidence=dict(evidence or {}),
        visibility_state=visibility_state,
        visibility_reasons=list(visibility_reasons),
        target_mapping=mapping,
        match_scope=scope,
        expected_assets=confirmed,
        unconfirmed_assets=unconfirmed,
        uncertainty=uncertainty,
        created_by=created_by,
    )


def impact_of(proposal: ResponseProposal) -> dict[str, Any]:
    """관측된 영향 범위와 미확인 범위를 돌려준다.

    이 응답의 핵심은 **둘의 분리** 다. 미확인 범위를 평균 내지 않고,
    감추지 않고, 확정 범위와 다른 칸에 둔다.
    """
    observed_assets = [a.get("asset_id") for a in proposal.expected_assets]
    unconfirmed_assets = [a.get("asset_id") for a in proposal.unconfirmed_assets]
    teams = sorted({a.get("team", "unknown") for a in proposal.expected_assets})
    criticality = max(
        (a.get("criticality", "low") for a in proposal.expected_assets),
        key=_criticality_rank, default="unknown",
    )

    return {
        "proposed_target": proposal.target_mapping.as_dict() if proposal.target_mapping else {},
        "match_scope": proposal.match_scope.as_dict() if proposal.match_scope else {},
        "ttl_seconds": proposal.ttl_seconds,
        # 확정된 것
        "observed_scope": {
            "asset_ids": observed_assets,
            "asset_count": len(observed_assets),
            "teams": teams,
            "highest_criticality": criticality,
        },
        # 확정되지 않은 것
        "unconfirmed_scope": {
            "asset_ids": unconfirmed_assets,
            "asset_count": len(unconfirmed_assets),
            "reasons": sorted(proposal.uncertainty),
            "note": "여기는 관측된 영향이 아니라 확인되지 않은 범위다",
        },
        "uncertainty": dict(proposal.uncertainty),
        "visibility_state": proposal.visibility_state,
        "visibility_reasons": list(proposal.visibility_reasons),
        "evidence": dict(proposal.evidence),
        "guardrails": {
            "no_auto_broadening": (
                "범위를 좁히지 못했으면 넓은 IP 차단으로 대체하지 않는다"
            ),
            "no_cached_mapping_execution": (
                "매핑이 오래되면 캐시된 매핑으로 실행하지 않는다"
            ),
            "observation_gate": (
                "관측이 stale/unknown 이면 신규 조치를 만들지 않는다"
            ),
            "approval_required": "이 응답은 제안일 뿐 승인된 조치 아니다",
        },
    }


def _criticality_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(value, 0)
