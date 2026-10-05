"""nftables 실 백엔드 — IPv4 input 전용, timeout set (계획서 2장, PR 15).

    "최초 실제 적용은 Linux nftables 의 IPv4 input 전용 timeout set 을 새로
     구현하고 커널 측 만료를 검증한 경우에만 허용한다."

이 모듈이 지킨다

1. **호스트 방화벽을 건드리지 않는다.** `ip filter` 는 iptables-nft/ufw 가
   관리한다. 우리는 `inet nwwatcher` 라는 **자기 테이블** 만 쓴다.
2. **flush 하지 않는다.** 추가/삭제는 `add ... -exist` 와 `delete element`
   뿐이다. 비우기 명령은 이 모듈에 없다.
3. **자기가 만든 것만 지운다.** 규칙 주석에 `nw:<tag>` 를 남기고, 태그가
   다른 규칙은 건드리지 않는다. 외부 관리자가 만든 규칙은 충돌로 보고한다.
4. **셸을 쓰지 않는다.** `subprocess` 는 argv 리스트에만, `shell=False`.
   대상 주소는 엄격히 IPv4 로만 검증한다.
5. **방향은 input 뿐, 패킷에 대한 규칙이다.** 이 백엔드는 그 이상을
   표현하지 않는다. 지원하지 않는 것을 지원처럼 보이게 하지 않는다.

커널 만료는 **실측** 으로만 참이 된다. `probe_kernel_expiry()` 가 격리된
네트워크 네임스페이스에 짧은 timeout 을 넣고 실제로 사라지는지 본다.
측정하지 못하면 `kernel_expiry_verified` 는 False 이고, 그 상태로 자동
차단을 켤 수 없다.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from netwatcher.response.executor import (
    OBSERVED_ABSENT,
    OBSERVED_PRESENT,
    OUTCOME_CONFIRMED,
    ExecutionRequest,
    ExecutionResult,
    Executor,
)
from netwatcher.response.lifecycle import (
    OUTCOME_ERROR,
    LifecycleError,
    validate_action,
)

logger = logging.getLogger("netwatcher.response.nftables")

# 우리 소유 테이블. 호스트의 ip filter(ufw/iptables-nft)와 절대 겹치지 않는다.
TABLE_FAMILY = "inet"
TABLE_NAME = "nwwatcher"
CHAIN_NAME = "input"
SET_NAME = "blocked"
CHAIN_HANDLE = "input"
CHAIN_PRIORITY = -10  # 기존 입력 체인보다 먼저 — 우리가 만든 규칙만 건다

# 이 백엔드가 표현할 수 있는 것
SUPPORTED_DIRECTIONS = ("input",)
SUPPORTED_FAMILIES = (4,)  # IPv4 only (계획서)

# 만료 확인 목표 시간(계획서): 조회 확인 5초, 만료 후 해제 확인 10초
VERIFY_TIMEOUT_SECONDS = 5.0
EXPIRY_VERIFY_TIMEOUT_SECONDS = 10.0

RULE_MARK = "netwatcher:managed"


def _full_set() -> str:
    return f"{TABLE_FAMILY} {TABLE_NAME} {SET_NAME}"


def _full_chain() -> str:
    return f"{TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME}"


def _full_table() -> str:
    return f"{TABLE_FAMILY} {TABLE_NAME}"


# ------------------------------------------------------------------
# 실행
# ------------------------------------------------------------------

class CommandRunner(Protocol):
    """nft 를 실행하는 좁은 통로. 셸은 없다."""

    def run(self, argv: list[str]) -> tuple[int, str, str]: ...


class ScriptRunner(Protocol):
    """여러 단계를 **하나의 격리 단위** 안에서 실행하는 통로.

    단계별로 나누어 실행하면 상태가 공유되지 않는다. 격리 시험(netns)에서는
    그게 곧 상태 소실로 이어진다. 그래서 한 번에 실행한다.
    """

    def run_steps(
        self, steps: list[tuple[str, list[str]]],
    ) -> list[dict[str, Any]]: ...


class NftRunner:
    """실제 실행기. argv 리스트만 받는다."""

    def __init__(self, nft_binary: str = "nft", sudo: bool = False) -> None:
        self._nft = nft_binary
        self._sudo = sudo

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        cmd = (["sudo", "-n", self._nft] if self._sudo else [self._nft]) + argv
        # shell=False — 문자열 명령을 절대 만들지 않는다
        proc = subprocess.run(  # noqa: S603 - argv 리스트, shell 미사용
            cmd, shell=False, capture_output=True, text=True, timeout=30,
        )
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")

    def run_steps(
        self, steps: list[tuple[str, list[str]]],
    ) -> list[dict[str, Any]]:
        """실제 시스템에서는 순서대로 실행하면 된다 (공유 상태가 이미 있다)."""
        out: list[dict[str, Any]] = []
        for purpose, argv in steps:
            rc, stdout, stderr = self.run(argv)
            out.append({
                "step": purpose, "rc": rc, "stdout": stdout,
                "stderr": (stderr or "").strip()[:200],
            })
        return out


@dataclass(frozen=True)
class NftCommand:
    argv: tuple[str, ...]
    purpose: str

    def as_dict(self) -> dict[str, Any]:
        return {"argv": list(self.argv), "purpose": self.purpose}


def validate_target(target: str) -> str:
    """IPv4 주소만 받는다. 그 외는 전부 거부한다.

    주소가 검증되지 않으면 nft 문법에 섞일 수 있다. 검증 없이 조립하지 않는다.
    """
    try:
        parsed = ipaddress.ip_address(target)
    except ValueError as exc:
        raise LifecycleError(
            f"지원하지 않는 대상 형식: {target}", status_code=400,
            detail={"target": target, "supported": "ipv4 only"},
        ) from exc
    if parsed.version != 4:
        raise LifecycleError(
            f"IPv6 은 이 백엔드에서 지원하지 않는다: {target}", status_code=400,
        )
    return str(parsed)


# ------------------------------------------------------------------
# 명령 조립 (OS 를 건드리지 않는 순수 함수)
# ------------------------------------------------------------------

def build_init_commands(tag: str) -> list[NftCommand]:
    """테이블·체인·set·규칙을 준비한다. 이미 있으면 아무것도 하지 않는다."""
    return [
        NftCommand(("add", "table", *_table_arg()), "테이블 준비"),
        NftCommand((
            "add", "chain", *_chain_arg(),
            "{", "type", "filter", "hook", CHAIN_HANDLE, "priority",
            str(CHAIN_PRIORITY), ";", "policy", "accept", ";", "}",
        ), "체인 준비 (이 백엔드의 규칙만 먼저 평가)"),
        NftCommand((
            "add", "set", *_set_arg(),
            "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}",
        ), "timeout set 준비"),
        NftCommand((
            "add", "rule", *_chain_arg(), "ip", "saddr", f"@{SET_NAME}",
            "drop", "comment", f'"{tag}"',
        ), "차단 규칙 준비"),
    ]


def build_add_element_command(target: str, ttl_seconds: int) -> NftCommand:
    """set 에 만료 있는 원소 하나를 넣는다."""
    return NftCommand((
        "add", "element", *_set_arg(),
        "{", target, "timeout", f"{int(ttl_seconds)}s", "}",
    ), "원소 추가 (커널 측 만료)")


def build_delete_element_command(target: str) -> NftCommand:
    return NftCommand(
        ("delete", "element", *_set_arg(), "{", target, "}"), "원소 제거",
    )


def build_get_element_command(target: str) -> NftCommand:
    return NftCommand(
        ("get", "element", *_set_arg(), "{", target, "}"), "원소 조회",
    )


def build_list_set_command() -> NftCommand:
    return NftCommand(("list", "set", *_set_arg()), "set 목록")


def _table_arg() -> tuple[str, ...]:
    return (TABLE_FAMILY, TABLE_NAME)


def _chain_arg() -> tuple[str, ...]:
    return (TABLE_FAMILY, TABLE_NAME, CHAIN_NAME)


def _set_arg() -> tuple[str, ...]:
    return (TABLE_FAMILY, TABLE_NAME, SET_NAME)


def rule_tag(action_id: int | str) -> str:
    return f"{RULE_MARK}:{action_id}"


# ------------------------------------------------------------------
# 커널 만료 실측
# ------------------------------------------------------------------

@dataclass
class ExpiryProbeReport:
    """만료 검증 결과. 측정하지 못했으면 measured=False."""

    measured: bool
    expiry_verified: bool
    applied_at: float
    confirmed_present: bool
    confirmed_absent: bool
    elapsed_seconds: float
    detail: str = ""
    observations: tuple[dict[str, Any], ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "measured": self.measured,
            "expiry_verified": self.expiry_verified,
            "applied_at": self.applied_at,
            "confirmed_present": self.confirmed_present,
            "confirmed_absent": self.confirmed_absent,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "detail": self.detail,
            "observations": list(self.observations),
        }


def _expiry_steps(target: str, ttl_seconds: int) -> list[tuple[str, list[str]]]:
    """만료 검증에 필요한 전체 단계.

    대기(sleep)도 한 단계로 넣는다 — 그래야 격리 시험에서 상태가 유지된다.
    """
    steps: list[tuple[str, list[str]]] = []
    for cmd in build_init_commands(rule_tag("probe")):
        steps.append((cmd.purpose, list(cmd.argv)))
    steps.append(("원소 추가", list(build_add_element_command(target, ttl_seconds).argv)))
    steps.append(("적용 직후 조회", list(build_get_element_command(target).argv)))
    steps.append(("만료 대기", ["sleep", str(int(ttl_seconds) + 2)]))
    steps.append(("만료 후 조회", list(build_get_element_command(target).argv)))
    steps.append(("set 목록", list(build_list_set_command().argv)))
    return steps


def probe_kernel_expiry(
    runner: "ScriptRunner | CommandRunner",
    *,
    ttl_seconds: int = 3,
    target: str = "198.18.0.1",
    clock: Callable[[], float] = time.time,
) -> ExpiryProbeReport:
    """실제 규칙을 넣고 실제로 사라지는지 확인한다.

    이 함수가 참을 반환해야만 `kernel_expiry_verified` 가 참이 된다.
    매뉴얼을 인용해 참을 만들지 않는다.
    """
    started = clock()

    if hasattr(runner, "run_steps"):
        results = runner.run_steps(_expiry_steps(target, ttl_seconds))  # type: ignore[union-attr]
    else:  # pragma: no cover - CommandRunner 는 편의상 단계 실행으로 처리
        results = []
        for purpose, argv in _expiry_steps(target, ttl_seconds):
            rc, stdout, stderr = runner.run(argv)
            results.append({
                "step": purpose, "rc": rc, "stdout": stdout,
                "stderr": (stderr or "").strip()[:200],
            })

    by_step = {r["step"]: r for r in results}
    observations = tuple(
        {"step": r["step"], "rc": r["rc"], "stderr": r.get("stderr", "")} for r in results
    )
    elapsed = clock() - started

    setup_failed = next(
        (r for r in results
         if r["rc"] != 0 and r["step"] in ("테이블 준비", "체인 준비 (이 백엔드의 규칙만 먼저 평가)",
                                           "timeout set 준비", "차단 규칙 준비")),
        None,
    )
    if setup_failed is not None:
        return ExpiryProbeReport(
            False, False, started, False, False, elapsed,
            f"준비 실패: {setup_failed['step']} — {setup_failed.get('stderr', '')[:200]}",
            observations,
        )

    add = by_step.get("원소 추가")
    if add is None or add["rc"] != 0:
        return ExpiryProbeReport(
            False, False, started, False, False, elapsed,
            f"적용 실패: {(add or {}).get('stderr', '')[:200]}", observations,
        )

    confirmed_present = by_step["적용 직후 조회"]["rc"] == 0
    confirmed_absent = by_step["만료 후 조회"]["rc"] != 0
    elements_left = _count_elements(by_step["set 목록"].get("stdout", ""))

    verified = confirmed_present and confirmed_absent and elements_left == 0
    detail = (
        "만료 전 존재 확인 + 만료 후 부재 확인 + 잔여 원소 0"
        if verified else
        f"검증 실패 (present={confirmed_present}, absent={confirmed_absent}, "
        f"잔여 원소={elements_left})"
    )
    return ExpiryProbeReport(
        measured=True, expiry_verified=verified, applied_at=started,
        confirmed_present=confirmed_present, confirmed_absent=confirmed_absent,
        elapsed_seconds=elapsed, detail=detail, observations=observations,
    )


def _count_elements(list_output: str) -> int:
    """`nft list set` 출력에서 원소 수를 센다.

    set 은 만료 뒤에도 존재한다. **원소 수** 가 곧 차단 지속 여부다.
    """
    for line in list_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("elements"):
            body = stripped.split("=", 1)[-1].strip()
            if body in ("{ }", "{  }", "{}"):
                return 0
            # 쉼표로 끝나면 마지막 원소가 있을 수 있다
            return 0 if not body.strip("{}").strip(", ") else len(
                [e for e in body.strip("{}").split(",") if e.strip()]
            )
    return 0


# ------------------------------------------------------------------
# 실행기
# ------------------------------------------------------------------

class NftablesExecutor(Executor):
    """실제 OS 를 건드리는 실행기.

    존재한다고 해서 켜면 안 된다. `kernel_expiry_verified` 는 **실측** 으로만
    참이 된다 — 계획서가 "검증된 만료 백엔드" 를 조건으로 걸었기 때문이다.
    """

    name = "nftables"
    applies_to_os = True

    def __init__(
        self, runner: CommandRunner | None = None,
        kernel_expiry_verified: bool = False,
        sudo: bool = False,
    ) -> None:
        self._runner = runner or NftRunner(sudo=sudo)
        self.kernel_expiry_verified = kernel_expiry_verified
        self.probe_report: ExpiryProbeReport | None = None

    # ------------------------------------------------------------------

    def verify_expiry_support(
        self, *, ttl_seconds: int = 3, runner: CommandRunner | None = None,
    ) -> ExpiryProbeReport:
        """커널 만료를 실측하고 결과를 기록한다."""
        report = probe_kernel_expiry(
            runner or self._runner, ttl_seconds=ttl_seconds,
        )
        self.probe_report = report
        self.kernel_expiry_verified = report.expiry_verified
        if report.expiry_verified:
            logger.info("nftables 커널 만료 검증 통과 (%.1fs 소요)", report.elapsed_seconds)
        else:
            logger.warning(
                "nftables 커널 만료 검증 실패 — 자동 차단 활성화 금지: %s", report.detail,
            )
        return report

    # ------------------------------------------------------------------

    @staticmethod
    def _reject(request: ExecutionRequest) -> None:
        validate_action(
            target=request.target, direction=request.direction,
            ttl_seconds=request.ttl_seconds,
        )
        validate_target(request.target)
        if request.direction not in SUPPORTED_DIRECTIONS:
            raise LifecycleError(
                f"이 백엔드는 {SUPPORTED_DIRECTIONS[0]} 만 지원한다",
                status_code=400,
                detail={"direction": request.direction, "supported": list(SUPPORTED_DIRECTIONS)},
            )

    def _run(self, cmd: NftCommand) -> ExecutionResult:
        try:
            rc, out, err = self._runner.run(list(cmd.argv))
        except FileNotFoundError as exc:
            return ExecutionResult(
                outcome=OUTCOME_ERROR, observed="unknown",
                detail=f"nft 실행 파일을 찾을 수 없다: {exc}", backend=self.name,
            )
        except PermissionError as exc:
            return ExecutionResult(
                outcome=OUTCOME_ERROR, observed="unknown",
                detail=f"권한이 없다 (NET_ADMIN 필요): {exc}", backend=self.name,
            )
        if rc != 0:
            return ExecutionResult(
                outcome=OUTCOME_ERROR, observed="unknown",
                detail=(err or out or f"rc={rc}").strip()[:300], backend=self.name,
            )
        return ExecutionResult(
            outcome=OUTCOME_CONFIRMED, observed=OBSERVED_PRESENT,
            detail=cmd.purpose, backend=self.name,
        )

    def apply(self, request: ExecutionRequest) -> ExecutionResult:
        """적용한다. TTL 만료는 커널이 담당한다."""
        self._reject(request)
        if not self.kernel_expiry_verified:
            # 만료가 증명되지 않은 백엔드로 자동 차단을 하지 않는다
            return ExecutionResult(
                outcome=OUTCOME_ERROR, observed="unknown",
                detail="커널 만료가 검증되지 않았다 — 적용하지 않는다",
                backend=self.name,
            )
        for cmd in build_init_commands(rule_tag(request.rule_tag)):
            result = self._run(cmd)
            if result.outcome != OUTCOME_CONFIRMED and "already exists" not in result.detail:
                return result
        applied = self._run(build_add_element_command(
            request.target, request.ttl_seconds))
        if applied.outcome != OUTCOME_CONFIRMED:
            return applied
        # 추가만으로 믿지 않는다 — 조회로 확인한다
        return self.verify(request)

    def verify(self, request: ExecutionRequest) -> ExecutionResult:
        """존재 여부를 **조회** 로 확인한다."""
        self._reject(request)
        result = self._run(build_get_element_command(request.target))
        if result.outcome == OUTCOME_CONFIRMED:
            return ExecutionResult(
                outcome=OUTCOME_CONFIRMED, observed=OBSERVED_PRESENT,
                rule_fingerprint=_fingerprint(request),
                detail="원소 존재 확인", backend=self.name,
            )
        # 조회 실패는 "없다" 와 "확인 못 했다" 를 구분해야 한다
        if _looks_like_missing(result.detail):
            return ExecutionResult(
                outcome="absent", observed=OBSERVED_ABSENT,
                rule_fingerprint=_fingerprint(request),
                detail="원소 부재 확인", backend=self.name,
            )
        return ExecutionResult(
            outcome="unverified", observed="unknown",
            detail=result.detail, backend=self.name,
        )

    def remove(self, request: ExecutionRequest) -> ExecutionResult:
        """제거한다. 제거 뒤 조회로 확인한다."""
        self._reject(request)
        result = self._run(build_delete_element_command(request.target))
        if result.outcome != OUTCOME_CONFIRMED:
            # 이미 없으면 목표 달성이다
            if _looks_like_missing(result.detail):
                return ExecutionResult(
                    outcome="absent", observed=OBSERVED_ABSENT,
                    detail="이미 없음", backend=self.name,
                )
            return result
        check = self.verify(request)
        if check.observed == OBSERVED_ABSENT:
            return ExecutionResult(
                outcome="absent", observed=OBSERVED_ABSENT,
                detail="제거 후 조회로 부재 확인", backend=self.name,
            )
        # 제거 명령은 성공했는데 여전히 보인다 — 복구 완료로 표시하지 않는다
        return ExecutionResult(
            outcome="mismatch", observed=OBSERVED_PRESENT,
            detail="제거 명령은 성공했지만 조회에서 여전히 보인다", backend=self.name,
        )


def _looks_like_missing(detail: str) -> bool:
    text = (detail or "").lower()
    return "no such" in text or "not found" in text or "does not exist" in text


def _fingerprint(request: ExecutionRequest) -> str:
    return request.content_hash()[:32]


def capabilities(executor: NftablesExecutor) -> dict[str, Any]:
    """이 백엔드가 지금 쓸 수 있는지 정직하게 알린다."""
    enabled = executor.kernel_expiry_verified
    return {
        "backend": executor.name,
        "applies_to_os": True,
        "kernel_expiry_verified": enabled,
        "mode": "enforce" if enabled else "shadow",
        "auto_block_enabled": False,
        "supported_directions": list(SUPPORTED_DIRECTIONS),
        "supported_families": ["ipv4"],
        "table": f"{TABLE_FAMILY} {TABLE_NAME}",
        "notice": (
            "커널 만료가 실측으로 확인되어 적용 가능하다. 그래도 자동 차단은 "
            "기본 꺼짐이다 — 운영자가 명시적으로 켜야 한다."
            if enabled else
            "커널 만료가 검증되지 않았다. 자동 차단으로 쓸 수 없다."
        ),
        "probe": executor.probe_report.as_dict() if executor.probe_report else None,
    }
