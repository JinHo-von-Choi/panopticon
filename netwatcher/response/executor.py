"""소권한 실행기 (계획서 2장, PR 13).

    "UI/정책평가와 작은 권한 실행기를 분리한다. 웹에는 방화벽 권한이 없고
     실행기는 허용된 대상·방향·TTL 만 받는다."

이 모듈이 **하지 않는 것** 이 이 장치의 전부다.

- 임의 명령을 받지 않는다. 대상·방향·TTL 만 받는다.
- 영구 적용을 받지 않는다.
- 확인하지 못하면 성공이라고 하지 않는다.

그리고 지금 이 백엔드는 **비어 있다.** 계획서:

    "현재 nftables 옵션은 미구현이며 재사용 가능한 완성 backend 로 간주하지
     않는다. 기존 iptables 자동 차단은 복구 검증 전 계속 비활성화한다."
    "검증된 만료 백엔드·권한 분리·적용 경로 증명이 하나라도 없으면
     shadow/제안만 출시한다."

그래서 `ShadowExecutor` 만 존재하고, 실제 OS 를 건드리는 백엔드는 없다.
`nftables` 을 "구현됨" 처럼 등록하는 것이 이 계획서에서 금지하는 바로 그것이다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

from netwatcher.response.lifecycle import (
    DEFAULT_TTL_SECONDS,
    OUTCOME_CONFIRMED,
    OUTCOME_UNVERIFIED,
    LifecycleError,
    candidate_hash,
    validate_action,
)

logger = logging.getLogger("netwatcher.response.executor")

APPLY = "apply"
VERIFY = "verify"
REMOVE = "remove"

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


class ShadowExecutor:
    """OS 를 건드리지 않는 실행기.

    의도를 기록하고 "적용했다"고 **주장하지 않는다**. 결과는 항상
    ``unverified`` 다. 이게 바로 계획서가 요구하는 shadow 모드다.

        "백업 예외를 동일 관측 스트림의 독립 상태에서 shadow 로 검증한다."
        "조치 후 보는 '차단됐을 연결' 을 표시할 뿐 실제 업무 무 영향을
         보장하지 않는다."

    실 운영 백엔드가 없을 때 이 클래스를 쓰는 것이 정직한 상태이고,
    "적용 성공" 을 표시하는 가짜 백엔드를 쓰는 것이 계획서가 금지하는 상태다.
    """

    name = "shadow"
    applies_to_os = False
    kernel_expiry_verified = False

    def __init__(self) -> None:
        self.intents: list[ExecutionRequest] = []

    def _accept(self, request: ExecutionRequest) -> None:
        # 실행 직전 마지막 검사 — 대상·방향·TTL 만이 들어온다
        validate_action(
            target=request.target,
            direction=request.direction,
            ttl_seconds=request.ttl_seconds,
        )

    def apply(self, request: ExecutionRequest) -> ExecutionResult:
        self._accept(request)
        self.intents.append(request)
        logger.info(
            "shadow 적용 의도 기록 (대상=%s 방향=%s ttl=%ds) — OS 변경 없음",
            request.target, request.direction, request.ttl_seconds,
        )
        return ExecutionResult(
            outcome=OUTCOME_UNVERIFIED,
            observed=OBSERVED_UNKNOWN,
            detail="shadow 모드 — OS 를 변경하지 않았으므로 적용을 확인하지 않았다",
            backend=self.name,
        )

    def verify(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult(
            outcome=OUTCOME_UNVERIFIED,
            observed=OBSERVED_UNKNOWN,
            detail="shadow 모드 — 조회할 실제 규칙이 없다",
            backend=self.name,
        )

    def remove(self, request: ExecutionRequest) -> ExecutionResult:
        return ExecutionResult(
            outcome=OUTCOME_UNVERIFIED,
            observed=OBSERVED_UNKNOWN,
            detail="shadow 모드 — 제거할 실제 규칙이 없다",
            backend=self.name,
        )


class UnavailableExecutor:
    """아직 구현되지 않은 백엔드를 명시적으로 표현한다.

    계획서: "현재 nftables 옵션은 미구현이며 재사용 가능한 완성 backend 로
    간주하지 않는다."

    미구현을 `None` 으로 남기면 호출자가 "설정 안 해서 안 하는 것" 과
    "구현돼서 안 되는 것" 을 구분할 수 없다. 그래서 실패를 raise 한다.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.applies_to_os = False
        self.kernel_expiry_verified = False

    def _refuse(self, op: str) -> ExecutionResult:
        raise LifecycleError(
            f"백엔드 '{self.name}' 는 구현되지 않았다 — {op} 을 수행할 수 없다",
            status_code=501,
            detail={
                "backend": self.name,
                "operation": op,
                "reason": "검증된 만료 백엔드가 없다 — shadow/제안만 출시한다",
            },
        )

    def apply(self, request: ExecutionRequest) -> ExecutionResult:
        return self._refuse(APPLY)

    def verify(self, request: ExecutionRequest) -> ExecutionResult:
        return self._refuse(VERIFY)

    def remove(self, request: ExecutionRequest) -> ExecutionResult:
        return self._refuse(REMOVE)


def build_executor(name: str, *, sudo: bool = False) -> Executor:
    """백엔드 이름으로 실행기를 만든다.

    nftables 은 **구현되어 있다** (PR 15). 하지만 곧바로 사용할 수 있는 것은
    아니다 — 커널 만료가 실측으로 확인되기 전까지 `kernel_expiry_verified`
    가 False 이고, 적용 시점에도 그 상태면 거부한다.

    그 검증을 언제 돌리냐가 중요하다. 기동 시 자동 실행하면 라이브 장비의
    방화벽에 우리 테이블을 만들어 두는 부작용이 생긴다. 그래서 검증은
    `python -m netwatcher.verify_nftables` 로 **운영자가 명시적으로** 돌린다.
    """
    if name == ShadowExecutor.name:
        return ShadowExecutor()
    if name == "nftables":
        from netwatcher.response.nftables_backend import NftablesExecutor

        return NftablesExecutor(kernel_expiry_verified=False, sudo=sudo)
    return UnavailableExecutor(name)


def executor_capabilities(name: str, executor: Executor | None = None) -> dict[str, Any]:
    """이 배포가 무엇을 할 수 있는지 정직하게 기술한다.

    대시보드는 이 값을 보고 "차단이 실제로 적용된다"고 말해서는 안 된다.
    """
    executor = executor or build_executor(name)
    if getattr(executor, "applies_to_os", False) and name == "nftables":
        from netwatcher.response.nftables_backend import capabilities as nft_caps

        return nft_caps(executor)  # type: ignore[arg-type]
    return {
        "backend": name,
        "applies_to_os": bool(getattr(executor, "applies_to_os", False)),
        "kernel_expiry_verified": bool(
            getattr(executor, "kernel_expiry_verified", False)
        ),
        "mode": "shadow" if not getattr(executor, "applies_to_os", False) else "enforce",
        "auto_block_enabled": False,
        "default_ttl_seconds": DEFAULT_TTL_SECONDS,
        "notice": (
            "OS 를 변경하는 백엔드가 없다. 표시되는 '적용' 은 의도 기록이며 "
            "차단이 적용되었다는 뜻이 아니다."
        ),
        "required_for_enforcement": [
            "검증된 만료 백엔드 (커널 측 만료 시험 통과)",
            "권한 분리 (웹에 방화벽 권한 없음)",
            "적용 경로 증명 (OS 적용 → 조회 확인 → 영수증)",
        ],
    }
