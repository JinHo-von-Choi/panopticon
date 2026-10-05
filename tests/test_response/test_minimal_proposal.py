"""최소 대응 제안 계약 테스트 (계획서 4장, PR 14).

계획서가 직접 지목한 시험 대상을 그대로 둔다.

> "공유 IP/NAT, DHCP 교체, 오래된 자산 정보, 관리망 대상, 서비스별 제한 미지원
>  백엔드를 시험한다. 제한을 좁힐 수 없으면 넓은 IP 차단으로 자동 대체하지
>  않는다. 응답 지연 시 캐시된 매핑으로 실행하지 않는다."

고정하는 것

- 좁힐 수 없으면 **제안하지 않는다** (넓은 IP 차단으로 대체 금지)
- 관측이 stale/unknown 이면 신규 조치 제안 금지
- 오래된 매핑은 불확실성으로 남고 실행 근거가 되지 못한다
- 확정된 영향 범위와 미확인 범위가 **분리**된다
- AI 는 scope·TTL 을 결정하지 못한다
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netwatcher.observability.observation import (
    STATE_OBSERVED,
    STATE_PARTIAL,
    STATE_STALE,
    STATE_UNKNOWN,
)
from netwatcher.response.proposals import (
    MAPPING_STALE_SECONDS,
    UNCERTAINTY_DHCP,
    UNCERTAINTY_NO_PRECISION,
    UNCERTAINTY_SHARED_IP,
    UNCERTAINTY_STALE_MAPPING,
    AssetMapping,
    MatchScope,
    ProposalError,
    build_proposal,
    impact_of,
)

NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)


def _mapping(**overrides) -> AssetMapping:
    kwargs = {
        "ip": "8.8.8.8", "asset_id": "srv-1", "team": "infra",
        "criticality": "high", "protected": False, "shared": False,
        "confirmed_at": NOW,
    }
    kwargs.update(overrides)
    return AssetMapping(**kwargs)


def _scope(**overrides) -> MatchScope:
    kwargs = {
        "kind": "port", "detail": {"ports": [22, 80]}, "service_aware": True,
    }
    kwargs.update(overrides)
    return MatchScope(**kwargs)


def _build(**overrides):
    base = {
        "source_ip": "8.8.8.8",
        "visibility_state": STATE_OBSERVED,
        "visibility_reasons": [],
        "mapping": _mapping(),
        "scope": _scope(),
        "peers": [
            {"asset_id": "db-1", "team": "data", "criticality": "critical", "confirmed": True},
            {"asset_id": "cache-1", "team": "data", "criticality": "low", "confirmed": False},
        ],
        "now": NOW,
    }
    base.update(overrides)
    return build_proposal(**base)


# ------------------------------------------------------------------
# 1) 좁힐 수 없으면 제안하지 않는다
# ------------------------------------------------------------------

def test_ip_only_scope_cannot_be_proposed() -> None:
    """IP 단위만 가능한 백엔드로 좁힌 제안을 만들지 않는다."""
    with pytest.raises(ProposalError) as exc:
        _build(scope=_scope(kind="ip", detail={"cidr": "8.8.8.8/32"}, service_aware=False))
    assert UNCERTAINTY_NO_PRECISION in str(exc.value.detail)
    assert exc.value.status_code == 409


def test_port_scope_without_ports_is_not_precise() -> None:
    scope = MatchScope(kind="port", detail={}, service_aware=True)
    assert scope.is_precise() is False
    with pytest.raises(ProposalError):
        _build(scope=scope)


def test_no_broadening_substitution() -> None:
    """제거 대신 대체하지 않는다 — 제안이 아예 만들어지지 않아야 한다."""
    with pytest.raises(ProposalError):
        _build(scope=_scope(kind="ip", detail={"cidr": "0.0.0.0/0"}))


def test_service_unaware_backend_still_usable_if_port_precise() -> None:
    """서비스 인식은 없어도 포트 단위면 좁힐 수 있다."""
    proposal = _build(scope=_scope(kind="port", detail={"ports": [443]},
                                   service_aware=False))
    assert proposal.match_scope.is_precise()


# ------------------------------------------------------------------
# 2) 관측 게이트
# ------------------------------------------------------------------

@pytest.mark.parametrize("state", [STATE_STALE, STATE_UNKNOWN])
def test_no_proposal_when_observation_untrustworthy(state: str) -> None:
    """stale/unknown 은 신규 조치 금지 조건이다."""
    with pytest.raises(ProposalError) as exc:
        _build(visibility_state=state, visibility_reasons=["heartbeat 누락"])
    assert exc.value.status_code == 409
    assert exc.value.detail["visibility_state"] == state


def test_partial_observation_adds_uncertainty() -> None:
    """부분 관측은 제안은 만들되 불확실성으로 남긴다."""
    proposal = _build(visibility_state=STATE_PARTIAL)
    assert "observation_not_trustworthy" in proposal.uncertainty


# ------------------------------------------------------------------
# 3) 매핑 — 공유 IP · 오래된 정보 · DHCP
# ------------------------------------------------------------------

def test_shared_ip_is_uncertain() -> None:
    proposal = _build(mapping=_mapping(shared=True))
    assert UNCERTAINTY_SHARED_IP in proposal.uncertainty


def test_stale_mapping_is_uncertain() -> None:
    old = NOW - timedelta(seconds=MAPPING_STALE_SECONDS + 60)
    proposal = _build(mapping=_mapping(confirmed_at=old))
    assert UNCERTAINTY_STALE_MAPPING in proposal.uncertainty


def test_unconfirmed_mapping_is_flagged_not_guessed() -> None:
    """확인되지 않은 매핑은 추측하지 않고 불확실성으로 남긴다.

    제안 단계에서 죽이는 것은 맞지 않다 — 제안은 사람이 읽는 것이고,
    '이 대상은 확인이 안 되었다'는 사실 자체가 정보다. **실행** 시점에
    막는다 (assert_mapping_fresh).
    """
    mapping = AssetMapping(ip="8.8.8.8", asset_id="srv-1", confirmed_at=None)
    assert mapping.is_stale(NOW)

    proposal = _build(mapping=mapping)
    assert UNCERTAINTY_STALE_MAPPING in proposal.uncertainty


def test_stale_mapping_blocks_execution() -> None:
    """오래된 매핑으로는 실행하지 않는다 (계획서 4장)."""
    from netwatcher.response.lifecycle import LifecycleError, assert_mapping_fresh

    old = NOW - timedelta(seconds=MAPPING_STALE_SECONDS + 60)
    with pytest.raises(LifecycleError) as exc:
        assert_mapping_fresh(old, now=NOW)
    assert exc.value.status_code == 409
    assert exc.value.detail["reason"] == "mapping_stale"


def test_unconfirmed_mapping_blocks_execution() -> None:
    from netwatcher.response.lifecycle import LifecycleError, assert_mapping_fresh

    with pytest.raises(LifecycleError) as exc:
        assert_mapping_fresh(None, now=NOW)
    assert exc.value.detail["reason"] == "mapping_unconfirmed"


def test_missing_mapping_blocks_proposal() -> None:
    with pytest.raises(ProposalError) as exc:
        _build(mapping=None)
    assert "매핑" in str(exc.value)


def test_dhcp_change_is_unknown_not_guessed() -> None:
    """DHCP 로 주소가 바뀔 수 있으면 확인된 자산으로 취급하지 않는다."""
    proposal = _build(
        peers=[
            {"asset_id": "laptop-1", "team": "user", "criticality": "low",
             "confirmed": False, "dynamic": True},
        ],
    )
    # 미확인 자산으로 분류된다
    assert proposal.expected_assets == []
    assert proposal.unconfirmed_assets[0]["asset_id"] == "laptop-1"
    assert UNCERTAINTY_DHCP not in proposal.uncertainty  # 명시 표시는 드문 상태


def test_management_network_target_marked_protected() -> None:
    proposal = _build(mapping=_mapping(protected=True))
    assert "protected_target" in proposal.uncertainty


# ------------------------------------------------------------------
# 4) 영향 범위 — 확정과 미확인의 분리
# ------------------------------------------------------------------

def test_impact_separates_confirmed_from_unconfirmed() -> None:
    """평균 내지 않고 감추지 않고 분리한다."""
    proposal = _build()
    impact = impact_of(proposal)

    assert impact["observed_scope"]["asset_ids"] == ["db-1"]
    assert impact["observed_scope"]["asset_count"] == 1
    assert impact["unconfirmed_scope"]["asset_ids"] == ["cache-1"]
    assert impact["unconfirmed_scope"]["asset_count"] == 1
    assert "관측된 영향이 아니라" in impact["unconfirmed_scope"]["note"]


def test_impact_reports_highest_criticality_of_confirmed_only() -> None:
    proposal = _build()
    impact = impact_of(proposal)
    assert impact["observed_scope"]["highest_criticality"] == "critical"


def test_impact_states_guardrails() -> None:
    guardrails = impact_of(_build())["guardrails"]
    assert "넓은 IP 차단으로 대체하지 않는다" in guardrails["no_auto_broadening"]
    assert "캐시된 매핑으로 실행하지 않는다" in guardrails["no_cached_mapping_execution"]
    assert "제안일 뿐 승인된 조치 아니다" in guardrails["approval_required"]


# ------------------------------------------------------------------
# 5) AI 는 승인·scope·TTL 을 결정하지 않는다
# ------------------------------------------------------------------

def test_ai_cannot_create_proposal() -> None:
    with pytest.raises(ProposalError) as exc:
        _build(created_by="ai")
    assert exc.value.status_code == 403


def test_ttl_bounds() -> None:
    with pytest.raises(ProposalError):
        _build(ttl_seconds=0)
    with pytest.raises(ProposalError):
        _build(ttl_seconds=100_000)


def test_ttl_is_carried_into_impact() -> None:
    proposal = _build(ttl_seconds=300)
    assert impact_of(proposal)["ttl_seconds"] == 300
