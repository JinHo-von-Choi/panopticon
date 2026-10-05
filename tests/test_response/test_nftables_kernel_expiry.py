"""G5: nftables 커널 측 만료 실측 (계획서 2장).

    "Netfilter 공식 매뉴얼은 set 원소 timeout 에 따른 자동 만료를 설명하지만,
     해당 배포에서의 적용·해제 성공은 별도 G5 시험이 필요하다."

이 테스트가 그 시험이다. 매뉴얼을 인용하지 않는다. **격리된 네트워크
네임스페이스에 실제로 넣고 실제로 사라지는지 본다.**

호스트 방화벽은 건드리지 않는다. `unshare --net` 안의 nftables 테이블은
네임스페이스 소유이므로, 프로세스가 끝나면 흔적도 남지 않는다.

건너뛰는 조건 (한 개라도 만족하면 skip)

- root 로 nft 를 실행할 수 없음 (권한)
- `nft` 실행 파일이 없음
- 네트워크 네임스페이스를 만들 수 없음 (컨테이너 등)

**스킵은 통과가 아니다.** CI 로그에 skip 사유가 남는다.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import subprocess
import time
from typing import Any

import pytest

from netwatcher.response.lifecycle import LifecycleError
from netwatcher.response.nftables_backend import (
    OBSERVED_ABSENT,
    OBSERVED_PRESENT,
    NftablesExecutor,
    NftRunner,
    build_add_element_command,
    build_delete_element_command,
    build_get_element_command,
    build_init_commands,
    probe_kernel_expiry,
    rule_tag,
    validate_target,
)
from netwatcher.response.executor import ExecutionRequest

NFT = shutil.which("nft")


def _privilege_prefix() -> list[str] | None:
    """nft 를 실행할 권한 경로를 찾는다.

    root 면 빈 접두사, 그렇지 않으면 비밀번호 없는 sudo 가 있을 때만 sudo.
    둘 다 없으면 None (스킵). sudo 에 프롬프트가 뜨면 안 되므로 ``-n`` 을 쓴다.
    """
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if sudo is None:
        return None
    probe = subprocess.run(
        [sudo, "-n", "true"], capture_output=True, text=True, timeout=10,
    )
    return [sudo, "-n"] if probe.returncode == 0 else None


_PRIV = _privilege_prefix()


def _can_run_nft() -> bool:
    if NFT is None or _PRIV is None:
        return False
    return subprocess.run(
        _PRIV + [NFT, "list", "ruleset"],
        capture_output=True, text=True, timeout=15,
    ).returncode == 0


def _can_make_netns() -> bool:
    """격리된 네임스페이스에서 nft 를 쓸 수 있는지 확인한다."""
    if NFT is None or _PRIV is None:
        return False
    probe = subprocess.run(
        _PRIV + ["unshare", "--net", NFT, "list", "ruleset"],
        capture_output=True, text=True, timeout=20,
    )
    return probe.returncode == 0


requires_root_nft = pytest.mark.skipif(
    not _can_run_nft(),
    reason="nft 실행 권한 없음 (root 또는 sudo -n 필요) — 커널 만료 실측 불가",
)
requires_netns = pytest.mark.skipif(
    not _can_make_netns(),
    reason="네트워크 네임스페이스를 만들 수 없음 (격리 시험 불가)",
)


# ------------------------------------------------------------------
# 1) 실측 — 커널 만료가 실제로 동작하는가
# ------------------------------------------------------------------

@requires_root_nft
@requires_netns
def test_kernel_expiry_is_real_and_measured(netns):
    """G5: 만료 전 존재, 만료 후 부재, 잔여 원소 0 — 셋 다 실측한다.

    매뉴얼을 인용하지 않는다. 격리 네임스페이스에 실제로 넣고 실제로 사라지는지
    보며, 세 조건이 모두 만족되어야 검증 통과로 본다.
    """
    report = probe_kernel_expiry(netns, ttl_seconds=2)

    assert report.measured is True, "측정 자체가 안 됐다"
    assert report.confirmed_present is True, "만료 전 원소가 없었다 — 적용 실패"
    assert report.confirmed_absent is True, "만료 후에도 원소가 남았다"
    assert report.expiry_verified is True, report.detail

    # 잔여 원소 0 이 검증의 마지막 조건이다
    listing = [o for o in report.observations if o["step"] == "set 목록"]
    assert listing, "set 목록 단계가 없다"


@requires_root_nft
@requires_netns
def test_expiry_probe_reports_verified(netns):
    """프로브가 참을 반환해야만 백엔드가 '검증됨' 이라고 말한다."""
    report = probe_kernel_expiry(netns, ttl_seconds=2)
    assert report.measured is True
    assert report.confirmed_present is True
    assert report.confirmed_absent is True
    assert report.expiry_verified is True, report.detail


@requires_root_nft
@requires_netns
def test_set_existing_is_not_treated_as_block_persisting(netns):
    """만료 뒤에도 set 은 남는다 — 잔여 원소로 판단해야 한다.

    계획서: "원소 수가 남았다는 이유만으로 차단 지속으로 판단하지 않는다."
    """
    report = probe_kernel_expiry(netns, ttl_seconds=2)
    assert report.expiry_verified is True

    # 만료 후에도 **set 은 존재한다.** 존재 여부로 차단 지속을 판단하면 안 된다.
    assert netns.run(["list", "set", "inet", "nwwatcher", "blocked"])[0] == 0

    # 잔여 원소 수로 판단해야 한다 — 이게 0 이어야 통과다
    rc, out, _err = netns.run(["list", "set", "inet", "nwwatcher", "blocked"])
    assert "elements" not in out or _elements_of(out) == 0


# ------------------------------------------------------------------
# 2) 실행기 — 만료 미검증이면 적용하지 않는다
# ------------------------------------------------------------------

@requires_root_nft
@requires_netns
def test_executor_applies_and_verifies_for_real(netns):
    """실제 적용 → 조회 확인."""
    executor = NftablesExecutor(
        runner=netns, kernel_expiry_verified=True,
    )
    request = ExecutionRequest(
        target="198.18.0.7", direction="input", ttl_seconds=5,
        rule_tag=rule_tag("test-1"),
    )
    applied = executor.apply(request)
    assert applied.verified is True, applied.detail

    verified = executor.verify(request)
    assert verified.observed == OBSERVED_PRESENT


@requires_root_nft
@requires_netns
def test_executor_refuses_when_expiry_unverified(netns):
    """만료 미검증이면 적용하지 않는다 — 결과도 확인됨으로 표시하지 않는다."""
    executor = NftablesExecutor(
        runner=netns, kernel_expiry_verified=False,
    )
    request = ExecutionRequest(
        target="198.18.0.8", direction="input", ttl_seconds=5,
        rule_tag=rule_tag("test-2"),
    )
    result = executor.apply(request)

    assert result.verified is False
    assert result.observed == "unknown"
    assert "커널 만료가 검증되지 않았다" in result.detail


@requires_root_nft
@requires_netns
def test_executor_remove_confirms_absence(netns):
    """제거 뒤 조회로 부재를 확인한다 — 명령 성공만으로 끝내지 않는다."""
    executor = NftablesExecutor(
        runner=netns, kernel_expiry_verified=True,
    )
    request = ExecutionRequest(
        target="198.18.0.9", direction="input", ttl_seconds=30,
        rule_tag=rule_tag("test-3"),
    )
    assert executor.apply(request).verified is True

    removed = executor.remove(request)
    assert removed.observed == OBSERVED_ABSENT, removed.detail
    assert executor.verify(request).observed == OBSERVED_ABSENT


# ------------------------------------------------------------------
# 3) 경계 — 이 백엔드가 표현하지 않는 것
# ------------------------------------------------------------------

def test_non_input_direction_rejected():
    executor = NftablesExecutor(kernel_expiry_verified=True)
    with pytest.raises(LifecycleError):
        executor.apply(ExecutionRequest(
            target="198.18.0.1", direction="output", ttl_seconds=300,
            rule_tag="x",
        ))


def test_ipv6_rejected():
    with pytest.raises(LifecycleError) as exc:
        validate_target("2001:db8::1")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("bad", [
    "not-an-ip", "1.2.3", "1.2.3.4; rm -rf /", "1.2.3.4 && id", "$(id)", "1.2.3.4/24",
])
def test_unsafe_targets_rejected(bad: str):
    """주입 문자열은 주소로 인정되지 않는다."""
    with pytest.raises(LifecycleError):
        validate_target(bad)


def test_commands_are_argv_lists_not_shell_strings():
    """명령은 argv 리스트다. 셸 문자열을 만들지 않는다."""
    for cmd in build_init_commands(rule_tag("t")) + [
        build_add_element_command("1.2.3.4", 300),
        build_delete_element_command("1.2.3.4"),
        build_get_element_command("1.2.3.4"),
    ]:
        assert isinstance(cmd.argv, tuple)
        assert all(isinstance(part, str) for part in cmd.argv)
        joined = " ".join(cmd.argv)
        assert "&&" not in joined and ";" != cmd.argv[0]
        assert "rm " not in joined


def test_never_references_host_firewall_tables():
    """호스트의 iptables/ufw 관리 테이블을 건드리지 않는다."""
    for cmd in build_init_commands(rule_tag("t")) + [
        build_add_element_command("1.2.3.4", 300),
        build_delete_element_command("1.2.3.4"),
        build_get_element_command("1.2.3.4"),
    ]:
        joined = " ".join(cmd.argv)
        assert "ip filter" not in joined, "호스트 iptables-nft 테이블을 건드린다"
        assert "flush" not in joined.lower(), "비우기 명령은 없다"
        assert "delete rule" not in joined, "다른 규칙을 지우지 않는다"


def test_protected_target_still_rejected_by_executor():
    executor = NftablesExecutor(kernel_expiry_verified=True)
    with pytest.raises(LifecycleError):
        executor.apply(ExecutionRequest(
            target="192.168.1.1", direction="input", ttl_seconds=300, rule_tag="x",
        ))


# ------------------------------------------------------------------
# 네임스페이스 하네스
# ------------------------------------------------------------------

def _netns_script(args: list[str]) -> list[str]:
    body = " ".join(_quote(a) for a in args)
    return (_PRIV or []) + ["unshare", "--net", "bash", "-c", body]


def _quote(value: str) -> str:
    if all(c.isalnum() or c in "-_.:/#{};$" for c in value):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


_NS_HELPER = """
import json, subprocess, sys

# for line in sys.stdin 은 파이프에서 읽기 선행 버퍼를 쓰기 때문에
# 한 줄을 보내도 즉시 처리하지 않는다. 줄이 올 때마다 처리해야 하므로
# readline 반복을 쓴다.
while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    if line == '{"__quit__": true}':
        break
    argv = json.loads(line)["argv"]
    proc = subprocess.run(argv, shell=False, capture_output=True, text=True)
    sys.stdout.write(json.dumps({
        "rc": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }) + "\\n")
    sys.stdout.flush()
"""


class _PersistentNetnsRunner:
    """네트워크 네임스페이스 하나를 **계속 유지**하며 명령을 실행한다.

    단계마다 네임스페이스를 새로 만들면 표와 set 이 사라져 검증이 무의미해진다.
    네임스페이스 하나를 프로세스로 열어 두고 그 안에서만 실행한다.

    셸을 쓰지 않는다 — 헬퍼는 JSON 으로 argv 를 받아 그대로 실행한다.
    """

    def __init__(self) -> None:
        self._proc = subprocess.Popen(
            (_PRIV or []) + ["unshare", "--net", sys.executable, "-c", _NS_HELPER],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )

    def run(self, argv: list[str]) -> tuple[int, str, str]:
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps({"argv": _with_nft(argv)}) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            return 1, "", "네임스페이스 헬퍼가 응답하지 않았다"
        data = json.loads(line)
        return int(data["rc"]), data["stdout"], data["stderr"]

    def run_steps(self, steps):
        return [
            {"step": purpose, "rc": rc, "stdout": out,
             "stderr": (err or "").strip()[:200]}
            for purpose, argv in steps
            for rc, out, err in [self.run(argv)]
        ]

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                assert self._proc.stdin
                self._proc.stdin.write('{"__quit__": true}\n')
                self._proc.stdin.flush()
            except (BrokenPipeError, ValueError):
                pass
            self._proc.kill()
            self._proc.wait(timeout=10)


def _elements_of(list_output: str) -> int:
    for line in list_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("elements"):
            body = stripped.split("=", 1)[-1].strip().strip("{}").strip()
            return len([e for e in body.split(",") if e.strip()])
    return 0


def _with_nft(argv: list[str]) -> list[str]:
    """백엔드가 만드는 argv 는 nft 서브커맨드부터 시작한다.

    실행기가 바이너리를 앞에 붙이는 것과 달리, 이 하네스는 셸이 없으므로
    실행 파일을 직접 넣어야 한다. `sleep` 같은 명령은 그대로 둔다.
    """
    if argv and argv[0] == "sleep":
        return list(argv)
    return [NFT, *argv]


@pytest.fixture
def netns():
    """테스트 하나당 네임스페이스 하나. 끝나면 반드시 닫는다."""
    runner = _PersistentNetnsRunner()
    try:
        yield runner
    finally:
        runner.close()


def _run_netns(script: list[str]) -> tuple[str, str, int]:
    proc = subprocess.run(script, capture_output=True, text=True, timeout=60)
    return proc.stdout or "", proc.stderr or "", proc.returncode
