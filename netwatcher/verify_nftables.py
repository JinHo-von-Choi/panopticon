"""nftables 커널 만료 검증 실행기 (계획서 2장, G5).

    "Netfilter 공식 매뉴얼은 set 원소 timeout 에 따른 자동 만료를 설명하지만,
     해당 배포에서의 적용·해제 성공은 별도 G5 시험이 필요하다."

    "최초 실제 적용은 Linux nftables 의 IPv4 input 전용 timeout set 을 새로
     구현하고 커널 측 만료를 검증한 경우에만 허용한다."

사용법::

    # 격리된 네임스페이스에서 검증한다 (호스트 방화벽을 건드리지 않는다)
    sudo -n python -m netwatcher.verify_nftables

    # 실제 장비에서 검증한다 — 우리 테이블만 만들고 만료까지 본다
    sudo -n python -m netwatcher.verify_nftables --live

종료 코드: 검증 통과 0, 실패 1. 실패한 채로 자동 차단을 켜면 안 된다.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any

from netwatcher.response.nftables_backend import (
    NftRunner,
    probe_kernel_expiry,
)


def _netns_runner() -> Any:
    """격리된 네임스페이스에서 실행하는 러너.

    라이브 장비의 방화벽을 건드리지 않고 같은 커널 만료 경로를 시험한다.
    """
    import shlex
    import shutil

    nft = shutil.which("nft")
    if nft is None:
        raise SystemExit("nft 실행 파일을 찾을 수 없다")

    def _with_binary(argv: list[str]) -> list[str]:
        # 백엔드의 argv 는 nft 서브커맨드부터 시작한다. 셸이 없으므로
        # 실행 파일을 직접 넣어야 한다.
        if argv and argv[0] == "sleep":
            return list(argv)
        return [nft, *argv]

    def run_steps(steps: list[tuple[str, list[str]]]) -> list[dict[str, Any]]:
        parts: list[str] = []
        for purpose, argv in steps:
            line = " ".join(shlex.quote(a) for a in _with_binary(argv))
            parts.append(f'echo "<<<{purpose}>>>"')
            parts.append(line)
            parts.append('echo "<<<rc=$?>>>"')
        body = "\n".join(parts)
        proc = subprocess.run(
            ["unshare", "--net", "bash", "-c", body],
            capture_output=True, text=True, timeout=120,
        )
        return _parse(stdout=proc.stdout or "", default_rc=proc.returncode)

    def _parse(stdout: str, default_rc: int) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        purpose: str | None = None
        buf: list[str] = []
        for line in stdout.splitlines():
            if line.startswith("<<<") and line.endswith(">>>"):
                marker = line[3:-3]
                if marker.startswith("rc="):
                    steps.append({
                        "step": purpose, "rc": int(marker[3:] or 1),
                        "stdout": "\n".join(buf), "stderr": "",
                    })
                    buf, purpose = [], None
                else:
                    purpose, buf = marker, []
            elif purpose is not None:
                buf.append(line)
        if purpose is not None and not steps:
            steps.append({
                "step": purpose, "rc": default_rc or 1,
                "stdout": "\n".join(buf), "stderr": "",
            })
        return steps

    class _Runner:
        def run_steps(self, s):  # noqa: D102
            return run_steps(s)

    return _Runner()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="nftables 커널 만료 검증 (G5)",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="격리 네임스페이스 대신 라이브 장비에서 검증한다 (우리 테이블만 사용)",
    )
    parser.add_argument("--ttl", type=int, default=3, help="검증에 쓸 만료 초")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print(
            "root 로 실행해야 한다. sudo -n python -m netwatcher.verify_nftables",
            file=sys.stderr,
        )
        return 2

    started = time.time()
    if args.live:
        runner: Any = NftRunner(sudo=False)
        scope = "라이브 장비 (inet nwwatcher 테이블만 사용, flush 없음)"
    else:
        runner = _netns_runner()
        scope = "격리 네트워크 네임스페이스 (호스트 방화벽 무영향)"

    report = probe_kernel_expiry(runner, ttl_seconds=args.ttl)
    payload = {"scope": scope, "elapsed_wall": round(time.time() - started, 2),
               **report.as_dict()}

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if report.expiry_verified:
        print("\n검증 통과: 커널 측 만료가 확인되었다. (그래도 자동 차단은 기본 꺼짐)")
        return 0
    print("\n검증 실패: 이 백엔드로 자동 차단을 켜면 안 된다.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
