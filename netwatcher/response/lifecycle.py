"""ResponseAction 생애주기 (계획서 2장, PR 13).

    "ResponseAction 은 requested → applying → active_verified → expiring →
     expired_verified, 수동 취소의 removed_verified 와 failed/unknown 을 둔다."

이 모듈이 지키는 세 가지

1. **`unknown` 은 성공도 해제도 아니다.** 확인하지 못한 것을 확인했다고
   기록하지 않는다. 상태를 지우지 않는다.
2. **승인과 적용은 분리된다.** `approve` 는 "사람이 결정했다" 이고
   `activate` 는 "OS 에 넣었다" 다. 승인한 해시·기준 버전이 바뀌면
   409 로 거부한다 — 다른 것으로 승인받은 결정을 재사용하지 않는다.
3. **재시도가 만료를 늘리지 않는다.** `expire_at` 은 최초 확정값이다.
   재시도로 연장되면 실제 노출 시간이 계획보다 길어진다.

영구 조치는 이 모듈에서 만들 수 없다. TTL 이 반드시 양수여야 한다.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

# 상태
STATE_REQUESTED = "requested"
STATE_APPLYING = "applying"
STATE_ACTIVE_VERIFIED = "active_verified"
STATE_EXPIRING = "expiring"
STATE_EXPIRED_VERIFIED = "expired_verified"
STATE_REMOVED_VERIFIED = "removed_verified"
STATE_FAILED = "failed"
STATE_UNKNOWN = "unknown"

STATES = (
    STATE_REQUESTED, STATE_APPLYING, STATE_ACTIVE_VERIFIED, STATE_EXPIRING,
    STATE_EXPIRED_VERIFIED, STATE_REMOVED_VERIFIED, STATE_FAILED, STATE_UNKNOWN,
)

# 영수증 결론 — 'unverified' 가 'confirmed' 와 같은 무게를 갖지 않는다
OUTCOME_CONFIRMED = "confirmed"
OUTCOME_ABSENT = "absent"
OUTCOME_MISMATCH = "mismatch"
OUTCOME_UNVERIFIED = "unverified"
OUTCOME_ERROR = "error"

# 계획서 2장 초기 제한
MAX_CONCURRENT = 3
MAX_PER_MINUTE = 1
DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 3600

# 자동 조치에서 기본 제외 대상 (관리 접속·DNS·게이트웨이·공유 NAT)
PROTECTED_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.2", "172.30.", "172.31.", "192.168.")


class LifecycleError(Exception):
    """생애주기 위반."""

    def __init__(self, message: str, status_code: int = 400, detail: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


# ------------------------------------------------------------------
# 전이표
# ------------------------------------------------------------------

# (현재 상태 → 허용되는 다음 상태)
TRANSITIONS: dict[str, tuple[str, ...]] = {
    STATE_REQUESTED: (STATE_APPLYING, STATE_FAILED, STATE_UNKNOWN),
    STATE_APPLYING: (STATE_ACTIVE_VERIFIED, STATE_FAILED, STATE_UNKNOWN),
    STATE_ACTIVE_VERIFIED: (STATE_EXPIRING, STATE_EXPIRED_VERIFIED,
                            STATE_REMOVED_VERIFIED, STATE_FAILED, STATE_UNKNOWN),
    STATE_EXPIRING: (STATE_EXPIRED_VERIFIED, STATE_ACTIVE_VERIFIED,
                     STATE_FAILED, STATE_UNKNOWN),
    STATE_EXPIRED_VERIFIED: (),
    STATE_REMOVED_VERIFIED: (),
    STATE_FAILED: (STATE_REQUESTED,),      # 명시적 재시도만
    STATE_UNKNOWN: (STATE_ACTIVE_VERIFIED, STATE_EXPIRED_VERIFIED,
                    STATE_REMOVED_VERIFIED, STATE_UNKNOWN),
}


def can_transition(current: str, nxt: str) -> bool:
    return nxt in TRANSITIONS.get(current, ())


def require_transition(current: str, nxt: str) -> None:
    if not can_transition(current, nxt):
        raise LifecycleError(
            f"상태 전이 불가: {current} → {nxt}", status_code=409,
            detail={"from": current, "to": nxt, "allowed": list(TRANSITIONS.get(current, ()))},
        )


# ------------------------------------------------------------------
# 승인 결함
# ------------------------------------------------------------------

@dataclass(frozen=True)
class Approval:
    """승인 시점에 고정되는 것.

    이 값이 approving 이후 바뀌면 409 다. "사람이 승인한 것" 과
    "실제로 적용되는 것" 이 달라지는 순간을 막는다.
    """

    approved_hash: str
    base_version: str
    approved_by: str
    approved_at: datetime
    target: str
    direction: str
    ttl_seconds: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "approved_hash": self.approved_hash,
            "base_version": self.base_version,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat(),
            "target": self.target,
            "direction": self.direction,
            "ttl_seconds": self.ttl_seconds,
        }


def candidate_hash(target: str, direction: str, ttl_seconds: int, scope: dict) -> str:
    """승인 대상의 내용 해시. 적용 직전까지 동일해야 한다."""
    payload = {
        "target": target, "direction": direction,
        "ttl_seconds": ttl_seconds, "scope": _canonical(scope),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _canonical(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def assert_activation_matches(
    approval: Approval,
    *,
    target: str, direction: str, ttl_seconds: int, scope: dict,
) -> None:
    """승인된 해시·기준 버전과 다르면 409 로 거부한다."""
    if target != approval.target:
        raise LifecycleError(
            "승인된 대상과 다릅니다", status_code=409,
            detail={"field": "target", "approved": approval.target, "requested": target},
        )
    if direction != approval.direction:
        raise LifecycleError(
            "승인된 방향과 다릅니다", status_code=409,
            detail={"field": "direction", "approved": approval.direction,
                    "requested": direction},
        )
    if ttl_seconds != approval.ttl_seconds:
        raise LifecycleError(
            "승인된 TTL 과 다릅니다", status_code=409,
            detail={"field": "ttl_seconds", "approved": approval.ttl_seconds,
                    "requested": ttl_seconds},
        )
    actual = candidate_hash(target, direction, ttl_seconds, scope)
    if actual != approval.approved_hash:
        raise LifecycleError(
            "승인 후 scope 가 변경되어 해시가 다릅니다 — 재승인이 필요합니다",
            status_code=409,
            detail={"field": "scope", "approved_hash": approval.approved_hash,
                    "current_hash": actual},
        )


# ------------------------------------------------------------------
# 정책 검사
# ------------------------------------------------------------------

def is_protected(target: str) -> bool:
    """자동 조치에서 기본 제외되는 대상인가.

    관리 접속·DNS·게이트웨이·공유 NAT 환경은 여기서 시작한다. 명시적
    제외 목록이 없으면 "모르겠으므로 건드리지 않는다" 가 기본이다.
    """
    return target.startswith(PROTECTED_PREFIXES) or target in (
        "127.0.0.1", "::1", "0.0.0.0",
    )


def validate_action(
    *, target: str, direction: str, ttl_seconds: int,
    protected: tuple[str, ...] = (), max_ttl: int = MAX_TTL_SECONDS,
) -> None:
    """실행 직전 마지막 검사. 조건을 만족하지 않으면 만들지 않는다."""
    if direction not in ("input", "output", "forward"):
        raise LifecycleError(f"허용되지 않은 방향: {direction}")
    if ttl_seconds <= 0:
        raise LifecycleError("영구 조치는 허용하지 않는다 — TTL 은 양수여야 한다")
    if ttl_seconds > max_ttl:
        raise LifecycleError(
            f"TTL {ttl_seconds}s 가 상한 {max_ttl}s 를 넘는다", status_code=409,
        )
    if not target:
        raise LifecycleError("대상이 비었다")
    if is_protected(target) or target in protected:
        raise LifecycleError(
            f"보호 대상({target})은 자동 조치 대상이 아니다", status_code=409,
            detail={"target": target},
        )


def assert_mapping_fresh(confirmed_at, now=None, max_age_seconds: int = 900) -> None:
    """매핑이 확인되지 않았거나 오래됐으면 실행을 거부한다.

    계획서: "응답 지연 시 캐시된 매핑으로 실행하지 않는다."

    제안 단계에서는 불확실성으로 남기되, **실행 시점에는 막는다.** 제안은
    사람이 읽는 것이고 실행은 목적을 가진 동작이므로 기준이 달라야 한다.
    """
    from datetime import datetime as _dt, timezone as _tz

    # timezone 은 클래스이므로 utc 인스턴스를 넘긴다 (클래스 자체는 tzinfo 가 아니다)
    base = now or _dt.now(_tz.utc)
    if confirmed_at is None:
        raise LifecycleError(
            "대상 매핑이 확인되지 않았다 — 캐시된 매핑으로 실행하지 않는다",
            status_code=409, detail={"reason": "mapping_unconfirmed"},
        )
    when = confirmed_at if isinstance(confirmed_at, _dt) else _dt.fromisoformat(
        str(confirmed_at).replace("Z", "+00:00"))
    if when.tzinfo is None:
        when = when.replace(tzinfo=_tz.utc)
    age = (base - when).total_seconds()
    if age > max_age_seconds:
        raise LifecycleError(
            f"대상 매핑이 {age:.0f}초 경과했다 — 캐시된 매핑으로 실행하지 않는다",
            status_code=409,
            detail={"reason": "mapping_stale", "age_seconds": round(age, 1)},
        )


class RateLimiter:
    """동시 3개 · 분당 1개 (계획서 2장 초기 제한)."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT,
                 max_per_minute: int = MAX_PER_MINUTE) -> None:
        self._max_concurrent = max_concurrent
        self._max_per_minute = max_per_minute
        self._active: set[int] = set()
        self._recent: list[float] = []

    def acquire(self, action_id: int, now: float | None = None) -> None:
        ts = now if now is not None else time.time()
        self._recent = [t for t in self._recent if ts - t < 60.0]
        if len(self._active) >= self._max_concurrent:
            raise LifecycleError(
                f"동시 적용 상한({self._max_concurrent}) 초과", status_code=429,
            )
        if len(self._recent) >= self._max_per_minute:
            raise LifecycleError(
                f"분당 적용 상한({self._max_per_minute}) 초과", status_code=429,
            )
        self._active.add(action_id)
        self._recent.append(ts)

    def release(self, action_id: int) -> None:
        self._active.discard(action_id)

    @property
    def active(self) -> int:
        return len(self._active)


# ------------------------------------------------------------------
# idempotency
# ------------------------------------------------------------------

def new_idempotency_key() -> str:
    return uuid.uuid4().hex[:24]


def set_expire_once(current: datetime | None, ttl_seconds: int,
                    now: datetime | None = None) -> datetime:
    """만료 시각은 **최초 확정값**이다.

    재시도가 호출돼도 이미 정해진 만료를 늘리지 않는다. 늘면 실제 노출
    시간이 계획보다 길어지고, 그 사실을 아무도 모른다.
    """
    if current is not None:
        return current
    base = now or datetime.now(timezone.utc)
    return base + timedelta(seconds=ttl_seconds)


# ------------------------------------------------------------------
# 조정 (reconcile)
# ------------------------------------------------------------------

@dataclass
class Reconciliation:
    """재시작 시 의도와 사실의 대조 결과."""

    action_id: int
    state: str
    desired: str          # "present" | "absent"
    observed: str         # "present" | "absent" | "unknown"
    disposition: str      # confirmed | mismatch | unverified
    detail: str = ""
    receipts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_unknown(self) -> bool:
        return self.observed == "unknown"

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "state": self.state,
            "desired": self.desired,
            "observed": self.observed,
            "disposition": self.disposition,
            "detail": self.detail,
            "unknown": self.is_unknown,
            "receipts": list(self.receipts),
        }


def reconcile(
    *, action: dict, observed: str, rule_fingerprint: str | None = None,
) -> Reconciliation:
    """DB 의 의도와 OS 의 사실을 대조한다.

    ``observed == 'unknown'`` 이면 결과는 **unknown** 이다. 확인하지 못한 것을
    존재/부재로 판정하지 않는다. 계획서: "unknown 을 성공이나 해제로 표시하지
    않는다."
    """
    state = action.get("state", STATE_REQUESTED)
    action_id = int(action.get("id") or 0)

    if observed == "unknown":
        return Reconciliation(
            action_id, STATE_UNKNOWN, "unknown", "unknown", OUTCOME_UNVERIFIED,
            detail="OS 조회 확인 불가 — 존재/부재를 판단하지 않는다",
        )

    # 만료가 지나 있으면 '없어야 함' 이 기대 상태다
    expire_at = action.get("expire_at")
    expired = False
    if expire_at is not None:
        try:
            when = expire_at if isinstance(expire_at, datetime) else datetime.fromisoformat(
                str(expire_at).replace("Z", "+00:00"))
            expired = when <= datetime.now(timezone.utc)
        except (ValueError, TypeError):
            expired = False

    if state == STATE_EXPIRED_VERIFIED or expired:
        desired = "absent"
        disposition = (
            OUTCOME_CONFIRMED if observed == "absent" else OUTCOME_MISMATCH
        )
        return Reconciliation(
            action_id, state, desired, observed, disposition,
            detail="" if disposition == OUTCOME_CONFIRMED
            else "만료되었는데 규칙이 남아 있다 — 만료와 GC 회수를 분리해 확인한다",
        )

    desired = "present"
    if observed == "present":
        # 제품이 만든 규칙인지 지문으로 확인한다
        if rule_fingerprint and action.get("rule_fingerprint") not in (None, rule_fingerprint):
            return Reconciliation(
                action_id, state, desired, observed, OUTCOME_MISMATCH,
                detail="규칙 지문이 다르다 — 외부 관리자가 바꿨을 수 있다",
            )
        return Reconciliation(
            action_id, STATE_ACTIVE_VERIFIED, desired, observed, OUTCOME_CONFIRMED,
            detail="규칙 존재 확인",
        )

    return Reconciliation(
        action_id, state, desired, observed, OUTCOME_ABSENT,
        detail="기대한 규칙이 없다 — intents 와 OS 가 어긋났다",
    )
