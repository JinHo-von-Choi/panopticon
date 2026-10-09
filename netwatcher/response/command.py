"""프로세스 간 조치 메시지와 실행 직전 승인 대조.

승인 근거는 실행기가 별도로 읽은 값이어야 한다. 메시지 안의 역할이나
승인 주장으로 실행을 허용하지 않는다.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from netwatcher.response.executor import ExecutionRequest
from netwatcher.response.lifecycle import LifecycleError, validate_action

MAX_COMMAND_BYTES = 8192
MAX_APPROVAL_AGE_SECONDS = 300
OPERATIONS = frozenset({"apply", "verify", "remove"})
FIELDS = frozenset({
    "version", "operation", "action_id", "idempotency_key", "actor_id",
    "actor_version", "ownership_version", "target", "direction",
    "ttl_seconds", "scope", "reason", "approval_expires_at",
})


def _refuse() -> LifecycleError:
    return LifecycleError("조치 메시지 또는 승인 근거가 유효하지 않습니다", 409)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite value")


def _uuid(value: object) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("non-canonical UUID")
    return value


def _positive(value: object) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise ValueError("positive integer required")
    return value


@dataclass(frozen=True)
class ActionAuthorization:
    """실행기가 독립 조회한 조치·계정·소유 관계의 일관된 스냅샷."""

    action_id: int
    idempotency_key: str
    approved_hash: str
    approved_at: datetime
    approval_expires_at: datetime
    actor_id: str
    actor_version: int
    actor_enabled: bool
    actor_role: str
    ownership_version: str
    mapping_confirmed_at: datetime
    executable: bool
    reason: str


@dataclass(frozen=True)
class ExecutionCommand:
    operation: str
    action_id: int
    idempotency_key: str
    actor_id: str
    actor_version: int
    ownership_version: str
    target: str
    direction: str
    ttl_seconds: int
    # JSON 바이트로 고정해 호출자가 승인 대조 이후 scope를 바꾸지 못한다.
    scope_json: bytes
    reason: str
    approval_expires_at: datetime

    @classmethod
    def from_bytes(cls, payload: bytes) -> ExecutionCommand:
        try:
            if type(payload) is not bytes or not 0 < len(payload) <= MAX_COMMAND_BYTES:
                raise ValueError("message size")
            value = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object,
                               parse_constant=_invalid_constant)
            if not isinstance(value, dict) or set(value) != FIELDS:
                raise ValueError("message fields")
            if type(value["version"]) is not int or value["version"] != 1:
                raise ValueError("protocol version")
            if value["operation"] not in OPERATIONS:
                raise ValueError("operation")
            scope = value["scope"]
            # 첫 실행 범위는 단일 호스트다. 임의 포트·명령·인터페이스는 받지 않는다.
            if not isinstance(scope, dict) or set(scope) - {"asset"}:
                raise ValueError("scope")
            if "asset" in scope and (
                not isinstance(scope["asset"], str) or not 0 < len(scope["asset"]) <= 128
                or not scope["asset"].isprintable()
            ):
                raise ValueError("asset")
            version = value["ownership_version"]
            if not isinstance(version, str) or not 0 < len(version) <= 64 or not version.isprintable():
                raise ValueError("ownership version")
            target = value["target"]
            address = ipaddress.ip_address(target)
            if (str(address) != target or address.is_loopback or address.is_unspecified
                    or address.is_multicast or address.is_link_local or "%" in target):
                raise ValueError("target")
            ttl = _positive(value["ttl_seconds"])
            validate_action(target=target, direction=value["direction"], ttl_seconds=ttl)
            reason = value["reason"]
            if not isinstance(reason, str) or not 0 < len(reason) <= 512 or not reason.isprintable():
                raise ValueError("reason")
            expiry_text = value["approval_expires_at"]
            if not isinstance(expiry_text, str) or len(expiry_text) > 40:
                raise ValueError("approval expiry")
            expiry = datetime.fromisoformat(expiry_text)
            if (expiry.utcoffset() != timezone.utc.utcoffset(expiry)
                    or expiry.isoformat() != expiry_text):
                raise ValueError("canonical UTC expiry required")
            return cls(
                operation=value["operation"], action_id=_positive(value["action_id"]),
                idempotency_key=_uuid(value["idempotency_key"]),
                actor_id=_uuid(value["actor_id"]), actor_version=_positive(value["actor_version"]),
                ownership_version=version, target=target, direction=value["direction"],
                ttl_seconds=ttl, scope_json=json.dumps(scope, sort_keys=True,
                    ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                reason=reason, approval_expires_at=expiry,
            )
        except (ValueError, TypeError, KeyError, RecursionError, LifecycleError):
            raise _refuse() from None

    def to_bytes(self) -> bytes:
        value = dict(self.__dict__)
        value["version"] = 1
        value["scope"] = json.loads(value.pop("scope_json"))
        value["approval_expires_at"] = self.approval_expires_at.isoformat()
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.from_bytes(payload)
        return payload

    def request(self) -> ExecutionRequest:
        return ExecutionRequest(
            target=self.target, direction=self.direction, ttl_seconds=self.ttl_seconds,
            rule_tag=f"nw-{self.action_id}", scope=json.loads(self.scope_json),
        )

    def validate_authorization(
        self, authorization: ActionAuthorization, *, now: datetime,
        protected: tuple[str, ...] = (), mapping_max_age_seconds: int = 900,
    ) -> ExecutionRequest:
        """호출 UID 검사와 독립 DB 조회를 마친 실행기가 사용한다.

        조회·해제에는 승인 유효기간을 적용하지 않아 만료 후에도 복구할 수 있다.
        계정과 조치의 연결·권한·버전 검사는 모든 작업에 적용한다.
        """
        timestamps = (now, authorization.approved_at, authorization.approval_expires_at,
                      authorization.mapping_confirmed_at)
        if any(t.tzinfo is None or t.utcoffset() is None for t in timestamps):
            raise _refuse()
        now = now.astimezone(timezone.utc)
        request = self.request()
        if (
            authorization.action_id != self.action_id
            or authorization.idempotency_key != self.idempotency_key
            or authorization.actor_id != self.actor_id
            or authorization.actor_version != self.actor_version
            or authorization.actor_enabled is not True
            or authorization.actor_role != "admin"
            or authorization.approved_hash != request.content_hash()
            or authorization.ownership_version != self.ownership_version
            or authorization.reason != self.reason
            or authorization.approval_expires_at != self.approval_expires_at
        ):
            raise _refuse()
        if self.operation == "apply":
            age = (now - authorization.approved_at).total_seconds()
            mapping_age = (now - authorization.mapping_confirmed_at).total_seconds()
            if (authorization.executable is not True
                    or not 0 <= age <= MAX_APPROVAL_AGE_SECONDS
                    or not authorization.approved_at < authorization.approval_expires_at
                    or not now < authorization.approval_expires_at
                    or not 0 <= mapping_age <= mapping_max_age_seconds):
                raise _refuse()
            validate_action(target=self.target, direction=self.direction,
                            ttl_seconds=self.ttl_seconds, protected=protected)
            address = ipaddress.ip_address(self.target)
            if any(address in ipaddress.ip_network(item, strict=False) for item in protected):
                raise _refuse()
        return request
