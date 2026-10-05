"""ResponseAction 생애주기 계약 테스트 (계획서 2장, PR 13).

고정하는 것

- **승인과 적용이 분리**되어 "승인만 되고 적용 안 됨" 이 표현된다
- 승인 후 대상·방향·TTL·scope 가 바뀌면 **409** 다
- **재시도가 만료를 늘리지 않는다**
- **`unknown` 을 성공이나 해제로 표시하지 않는다**
- 영구 조치가 불가능하다
- 실행기에 대상·방향·TTL **외의 것을 넘길 수 없다**
- 미구현 백엔드는 조용히 대체되지 않는다
- 재시작 조정기가 의도와 사실을 대조하고, 모르면 `unknown` 이다

실제 OS 를 건드리는 테스트는 없다. 만료 백엔드가 검증되지 않았으므로
실제 적용 시험은 하지 않는다. 계획서가 그 시험을 요구한다면 그건 사람이
G5 에서 수행하는 일이다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netwatcher.response.executor import (
    OBSERVED_UNKNOWN,
    ExecutionRequest,
    ShadowExecutor,
    UnavailableExecutor,
    build_executor,
    executor_capabilities,
)
from netwatcher.response.lifecycle import (
    OUTCOME_CONFIRMED,
    OUTCOME_UNVERIFIED,
    STATE_ACTIVE_VERIFIED,
    STATE_APPLYING,
    STATE_EXPIRED_VERIFIED,
    STATE_FAILED,
    STATE_REMOVED_VERIFIED,
    STATE_REQUESTED,
    STATE_UNKNOWN,
    Approval,
    LifecycleError,
    RateLimiter,
    assert_activation_matches,
    can_transition,
    candidate_hash,
    is_protected,
    reconcile,
    require_transition,
    set_expire_once,
    validate_action,
)


def _approval(**overrides) -> Approval:
    scope = overrides.pop("scope", {"asset": "srv-1"})
    target = overrides.pop("target", "8.8.8.8")
    direction = overrides.pop("direction", "input")
    ttl = overrides.pop("ttl_seconds", 300)
    kwargs = {
        "approved_hash": candidate_hash(target, direction, ttl, scope),
        "base_version": "v1",
        "approved_by": "admin",
        "approved_at": datetime.now(timezone.utc),
        "target": target,
        "direction": direction,
        "ttl_seconds": ttl,
    }
    kwargs.update(overrides)
    return Approval(**kwargs)


# ------------------------------------------------------------------
# 1) 상태 전이
# ------------------------------------------------------------------

def test_documented_state_path_is_walkable() -> None:
    """계획서의 상태 순서를 그대로 지킨다."""
    path = [
        STATE_REQUESTED, STATE_APPLYING, STATE_ACTIVE_VERIFIED,
        STATE_EXPIRED_VERIFIED,
    ]
    for current, nxt in zip(path, path[1:]):
        assert can_transition(current, nxt), f"{current} → {nxt} 가 막혀 있다"


def test_manual_cancel_path_exists() -> None:
    assert can_transition(STATE_ACTIVE_VERIFIED, STATE_REMOVED_VERIFIED)


def test_expired_is_terminal() -> None:
    """만료 확인이 끝난 뒤에는 임의 전이가 없다."""
    assert not can_transition(STATE_EXPIRED_VERIFIED, STATE_REQUESTED)
    assert not can_transition(STATE_EXPIRED_VERIFIED, STATE_APPLYING)


def test_illegal_transition_raises_409() -> None:
    with pytest.raises(LifecycleError) as exc:
        require_transition(STATE_EXPIRED_VERIFIED, STATE_ACTIVE_VERIFIED)
    assert exc.value.status_code == 409


# ------------------------------------------------------------------
# 2) 승인 ↔ 적용 불일치 = 409
# ------------------------------------------------------------------

def test_activation_matches_when_unchanged() -> None:
    approval = _approval()
    assert_activation_matches(
        approval, target="8.8.8.8", direction="input", ttl_seconds=300,
        scope={"asset": "srv-1"},
    )


@pytest.mark.parametrize("kwargs,field", [
    ({"target": "1.1.1.1"}, "target"),
    ({"direction": "output"}, "direction"),
    ({"ttl_seconds": 600}, "ttl_seconds"),
    ({"scope": {"asset": "srv-2"}}, "scope"),
])
def test_drift_after_approval_is_409(kwargs, field) -> None:
    """승인 후 하나라도 바뀌면 재승인이 필요하다."""
    approval = _approval()
    base = {
        "target": "8.8.8.8", "direction": "input",
        "ttl_seconds": 300, "scope": {"asset": "srv-1"},
    }
    base.update(kwargs)
    with pytest.raises(LifecycleError) as exc:
        assert_activation_matches(approval, **base)
    assert exc.value.status_code == 409
    assert exc.value.detail["field"] == field


# ------------------------------------------------------------------
# 3) 만료는 한 번만 정한다
# ------------------------------------------------------------------

def test_expire_at_is_set_once() -> None:
    first = set_expire_once(None, 300)
    second = set_expire_once(first, 300)
    assert second == first, "재시도가 만료를 늘렸다"


def test_expire_at_uses_ttl() -> None:
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    result = set_expire_once(None, 300, now=now)
    assert result == now + timedelta(seconds=300)


# ------------------------------------------------------------------
# 4) 정책 — 영구 금지 · 보호 대상
# ------------------------------------------------------------------

def test_permanent_action_impossible() -> None:
    with pytest.raises(LifecycleError):
        validate_action(target="8.8.8.8", direction="input", ttl_seconds=0)


def test_ttl_ceiling_enforced() -> None:
    with pytest.raises(LifecycleError) as exc:
        validate_action(target="8.8.8.8", direction="input", ttl_seconds=86_400)
    assert exc.value.status_code == 409


@pytest.mark.parametrize("target", [
    "192.168.1.10", "10.0.0.5", "172.16.0.1", "127.0.0.1",
])
def test_protected_targets_excluded_by_default(target: str) -> None:
    """관리 접속·내부망은 자동 조치 대상이 아니다."""
    assert is_protected(target)
    with pytest.raises(LifecycleError):
        validate_action(target=target, direction="input", ttl_seconds=300)


def test_explicit_protection_list_honored() -> None:
    with pytest.raises(LifecycleError):
        validate_action(
            target="8.8.8.8", direction="input", ttl_seconds=300,
            protected=("8.8.8.8",),
        )


def test_bad_direction_rejected() -> None:
    with pytest.raises(LifecycleError):
        validate_action(target="8.8.8.8", direction="sideways", ttl_seconds=300)


# ------------------------------------------------------------------
# 5) 속도 제한 (동시 3 · 분당 1)
# ------------------------------------------------------------------

def test_rate_limits() -> None:
    limiter = RateLimiter(max_concurrent=3, max_per_minute=10)
    for i in range(3):
        limiter.acquire(i)
    with pytest.raises(LifecycleError) as exc:
        limiter.acquire(99)
    assert exc.value.status_code == 429


def test_per_minute_limit() -> None:
    limiter = RateLimiter(max_concurrent=10, max_per_minute=1)
    limiter.acquire(1)
    with pytest.raises(LifecycleError) as exc:
        limiter.acquire(2)
    assert exc.value.status_code == 429


def test_release_frees_slot() -> None:
    limiter = RateLimiter(max_concurrent=1, max_per_minute=10)
    limiter.acquire(1)
    limiter.release(1)
    limiter.acquire(2)


# ------------------------------------------------------------------
# 6) 실행기 — 권한 경계
# ------------------------------------------------------------------

def test_executor_only_accepts_target_direction_ttl() -> None:
    """ExecutionRequest 에 실행할 수 있는 값 외의 필드가 없다."""
    fields = set(ExecutionRequest.__dataclass_fields__)
    assert fields == {"target", "direction", "ttl_seconds", "rule_tag", "scope"}


def test_shadow_executor_never_claims_success() -> None:
    """shadow 는 '적용됐다' 고 말하지 않는다."""
    executor = ShadowExecutor()
    request = ExecutionRequest(
        target="8.8.8.8", direction="input", ttl_seconds=300, rule_tag="nw-1",
    )
    result = executor.apply(request)

    assert result.verified is False
    assert result.outcome == OUTCOME_UNVERIFIED
    assert result.observed == OBSERVED_UNKNOWN
    assert executor.applies_to_os is False


def test_shadow_records_intent() -> None:
    executor = ShadowExecutor()
    request = ExecutionRequest(
        target="8.8.8.8", direction="input", ttl_seconds=300, rule_tag="nw-1",
    )
    executor.apply(request)
    assert executor.intents == [request]


def test_shadow_rejects_protected_target() -> None:
    executor = ShadowExecutor()
    with pytest.raises(LifecycleError):
        executor.apply(ExecutionRequest(
            target="192.168.1.1", direction="input", ttl_seconds=300, rule_tag="x",
        ))


def test_unimplemented_backend_raises_not_falls_back() -> None:
    """미구현 백엔드는 예외로 알린다 — 조용히 대체하지 않는다."""
    executor = UnavailableExecutor("nftables")
    with pytest.raises(LifecycleError) as exc:
        executor.apply(ExecutionRequest(
            target="8.8.8.8", direction="input", ttl_seconds=300, rule_tag="x",
        ))
    assert exc.value.status_code == 501


def test_build_executor_does_not_silently_upgrade() -> None:
    """미지원 백엔드는 여전히 예외로 알린다.

    nftables 는 PR 15 에서 **새로 구현** 됐다. 미구임과 쓰면 안 된다는 계획서
    문장은 "기존에 미구현이던 nftables 옵션" 에 대한 것이었고, 그 옵션을
    완성 backend 로 간주하지 말라 한 것이다. 새로 구현했으므로
    UnavailableExecutor 가 아니다. 그래도 **쓸 수 있다고 말하지는 않는다.**
    """
    from netwatcher.response.nftables_backend import NftablesExecutor

    assert isinstance(build_executor("shadow"), ShadowExecutor)
    nft = build_executor("nftables")
    assert isinstance(nft, NftablesExecutor)
    # 검증 전에는 스스로를 쓸 수 있다고 말하지 않는다
    assert nft.applies_to_os is True
    assert nft.kernel_expiry_verified is False

    # 모르는 백엔드는 여전히 예외로 알린다
    assert isinstance(build_executor("ipfw"), UnavailableExecutor)


def test_capabilities_are_honest() -> None:
    """구현되어 있다는 것과 쓸 수 있다는 것을 구분해 말한다.

    PR 15 전에는 `applies_to_os` 가 false 였다 (미구현). 지금은 백엔드가 있으므로
    true 다. 하지만 `kernel_expiry_verified` 가 false 인 동안 **mode 는 shadow**
    이고 auto_block 도 꺼져 있다. 구현됨 ≠ 적용 가능.
    """
    caps = executor_capabilities("nftables")
    assert caps["applies_to_os"] is True          # 실제로 OS 를 건드리는 백엔드
    assert caps["kernel_expiry_verified"] is False  # 하지만 만료 미검증
    assert caps["auto_block_enabled"] is False
    assert caps["mode"] == "shadow"               # 그래서 아직 강제가 아니다
    assert caps["supported_directions"] == ["input"]
    assert caps["supported_families"] == ["ipv4"]
    assert "검증되지 않았다" in caps["notice"]


def test_shadow_capabilities_unchanged() -> None:
    """shadow 는 OS 를 건드리지 않는다고 계속 말한다."""
    caps = executor_capabilities("shadow")
    assert caps["applies_to_os"] is False
    assert caps["auto_block_enabled"] is False
    assert caps["mode"] == "shadow"
    assert "차단이 적용되었다는 뜻이 아니다" in caps["notice"]
    assert caps["required_for_enforcement"]


# ------------------------------------------------------------------
# 7) 조정 (재시작 대조)
# ------------------------------------------------------------------

def test_reconcile_present_is_confirmed() -> None:
    result = reconcile(action={"id": 1, "state": STATE_ACTIVE_VERIFIED}, observed="present")
    assert result.disposition == OUTCOME_CONFIRMED
    assert result.state == STATE_ACTIVE_VERIFIED


def test_reconcile_unknown_is_unknown_not_success() -> None:
    """조회 실패를 존재로 판정하지 않는다."""
    result = reconcile(action={"id": 1, "state": STATE_ACTIVE_VERIFIED}, observed="unknown")
    assert result.state == STATE_UNKNOWN
    assert result.is_unknown
    assert result.disposition == OUTCOME_UNVERIFIED


def test_reconcile_expiry_separate_from_gc() -> None:
    """만료 뒤 규칙이 남아 있으면 불일치 — '원소 수' 로 판단하지 않는다."""
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    result = reconcile(
        action={"id": 1, "state": STATE_ACTIVE_VERIFIED, "expire_at": past},
        observed="present",
    )
    assert result.disposition == "mismatch"
    assert "GC" in result.detail


def test_reconcile_expiry_confirmed_when_absent() -> None:
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    result = reconcile(
        action={"id": 1, "state": STATE_ACTIVE_VERIFIED, "expire_at": past},
        observed="absent",
    )
    assert result.disposition == OUTCOME_CONFIRMED


def test_reconcile_detects_external_modification() -> None:
    """외부 관리자가 규칙을 바꾸면 충돌로 표시한다."""
    result = reconcile(
        action={"id": 1, "state": STATE_ACTIVE_VERIFIED, "rule_fingerprint": "aaa"},
        observed="present", rule_fingerprint="bbb",
    )
    assert result.disposition == "mismatch"
    assert "외부 관리자" in result.detail


def test_reconcile_detects_missing_rule() -> None:
    result = reconcile(
        action={"id": 1, "state": STATE_ACTIVE_VERIFIED}, observed="absent",
    )
    assert result.disposition == "absent"
    assert "어긋났다" in result.detail
