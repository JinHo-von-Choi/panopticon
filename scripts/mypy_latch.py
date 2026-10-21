"""mypy 오류 수가 **버전별 기준선**을 넘지 않는지 확인한다.

왜 버전별인가: CI 는 Python 3.12 와 3.13 을 모두 돌린다. 같은 코드라도
표준 라이브러리 스텁이 달라서 오류 수가 다르다. 그래서 기준선도 다르다.
2026-10-22 실측: 3.13 은 190 개, 3.12 는 그보다 많다.

이전 래치는 상한 하나(196) 를 모든 버전에 적용했다. 그 결과 3.13 이
190 개인 상태에서도 6 개의 여유가 남아 있었다 — 오류를 줄여도 CI 는
똑같이 초록이라 **개선이 신호로 표현되지 않았다**.

기준선은 `scripts/mypy_baseline.json` 에 있다. 오류는 늘릴 수만 있다.
하나를 고칠 때마다 해당 버전의 값을 내린다.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = Path(__file__).resolve().parent / "mypy_baseline.json"

# CI 가 쓰던 오류 판정 패턴과 같다.
ERROR_PATTERN = re.compile(r"^[^ ]+\.py:[0-9]+: error:")

# 실패했을 때 표시할 오류 줄 수. 전부 dump 하면 로그가 읽기 힘들다.
MAX_REPORTED_ERRORS = 20


def count_errors(output: str) -> int:
    """mypy 출력에서 오류 줄의 수를 센다."""
    return sum(1 for line in output.splitlines() if ERROR_PATTERN.match(line))


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, int]:
    """기준선 파일을 읽는다. 설명용 키(_ 로 시작)는 무시한다."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        key: int(value)
        for key, value in raw.items()
        if not key.startswith("_")
    }


def baseline_for(version: str, baseline: dict[str, int]) -> tuple[int, str]:
    """주어진 Python 버전의 기준선을 돌려준다.

    알 수 없는 버전이면 **가장 큰 기준선**을 쓴다 — 새 버전이 조용히
    통과하지 않게 하기 위해서다.
    """
    key = ".".join(version.split(".")[:2])
    if key in baseline:
        return baseline[key], key
    if not baseline:
        return 0, key
    return max(baseline.values()), f"{key} (알 수 없음 — 최대값 사용)"


def run_mypy(target: str = "netwatcher") -> tuple[int, str]:
    """mypy 를 돌려 (오류 수, 출력) 을 돌려준다.

    mypy 는 오류가 있으면 0 이 아닌 코드로 끝나므로 실패를 삼킨다 —
    판정은 오류 수로 한다.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", target],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return count_errors(output), output


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    target = argv[0] if argv else "netwatcher"

    try:
        baseline = load_baseline()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"기준선 파일을 읽을 수 없다: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    errors, output = run_mypy(target)
    limit, key = baseline_for(f"{sys.version_info.major}.{sys.version_info.minor}", baseline)

    print(f"mypy errors={errors} baseline={limit} (python {key})")
    if errors > limit:
        print(
            f"타입 검사 오류가 기준선({limit})을 넘었다: {errors} "
            f"— 오류는 늘릴 수만 있다. 고친 뒤 scripts/mypy_baseline.json 의 "
            f"{key} 값을 내리라.",
            file=sys.stderr,
        )
        reported = [
            line for line in output.splitlines()
            if ERROR_PATTERN.match(line)
        ][:MAX_REPORTED_ERRORS]
        for line in reported:
            print(line, file=sys.stderr)
        if len(reported) >= MAX_REPORTED_ERRORS:
            print(f"... (앞 {MAX_REPORTED_ERRORS}건만 표시)", file=sys.stderr)
        return 1
    if errors < limit:
        # 줄인 만큼 기준선을 내리라는 신호를 남긴다 — 초록이 같아도
        # 개선이 보인다.
        print(
            f"기준선({limit})보다 {limit - errors} 개 적다 — "
            f"scripts/mypy_baseline.json 의 {key} 값을 {errors} 로 내리라."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
