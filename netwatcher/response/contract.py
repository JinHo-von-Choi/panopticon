"""조치 실행기 계약.

실행기(방화벽 백엔드)가 웹 계층과 어떤 값을 주고받는지 정의한다.
백엔드 구현과 웹 계층이 같은 계약을 여기서 가져간다 — 서로를
직접 가져오면 순환이 생긴다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from netwatcher.response.lifecycle import OUTCOME_CONFIRMED, candidate_hash

# 확인 결과를 담는 봉투. 'unknown' 은 값으로 존재한다 — 없는 게 아니다
OBSERVED_PRESENT = "present"
OBSERVED_ABSENT = "absent"
OBSERVED_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ExecutionRequest:
    """실행기에 전달되는 값. 이 이상은 받지 않는다."""

    target: str
    direction: str
    ttl_seconds: int
    rule_tag: str
    scope: dict[str, Any] = field(default_factory=dict)

    def content_hash(self) -> str:
        return candidate_hash(self.target, self.direction, self.ttl_seconds, self.scope)


@dataclass(frozen=True, kw_only=True)
class ExpiringExecutionRequest(ExecutionRequest):
    """실행기가 DB에서 확정한 만료 시각을 붙이는 내부 요청."""

    expires_at: datetime | None


@dataclass
class ExecutionResult:
    """실행 결과. 확인되지 않으면 confirmed 가 아니다."""

    outcome: str                 # confirmed | unverified | error | absent | mismatch
    observed: str                # present | absent | unknown
    rule_fingerprint: str | None = None
    detail: str = ""
    backend: str = "shadow"

    @property
    def verified(self) -> bool:
        return self.outcome == OUTCOME_CONFIRMED and self.observed == OBSERVED_PRESENT

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "observed": self.observed,
            "rule_fingerprint": self.rule_fingerprint,
            "detail": self.detail,
            "backend": self.backend,
            "verified": self.verified,
        }


class Executor(Protocol):
    """실행기 계약. 웹 계층은 이 인터페이스만 본다."""

    name: str
    applies_to_os: bool

    def apply(self, request: ExecutionRequest) -> ExecutionResult: ...
    def verify(self, request: ExecutionRequest) -> ExecutionResult: ...
    def remove(self, request: ExecutionRequest) -> ExecutionResult: ...
