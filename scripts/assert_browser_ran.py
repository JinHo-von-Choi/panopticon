#!/usr/bin/env python3
"""브라우저 시험이 실제로 실행됐는지 확인한다.

브라우저 시험은 환경(Chrome·Node·PANOPTICON_PLAYWRIGHT_CORE)이 없으면
건너뛴다. 건너뛴 채 CI 가 초록이면 브라우저 시험이 없는 것과 같다. 그래서
수집 건수와 실행 건수를 비교해 **실행된 시험이 하나도 없으면** 실패시킨다.

사용법::

    python -m pytest tests/ -k browser -q --junitxml=/tmp/browser.xml
    python scripts/assert_browser_ran.py /tmp/browser.xml
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("사용법: assert_browser_ran.py <junit.xml>", file=sys.stderr)
        return 2
    path = Path(argv[0])
    if not path.exists():
        print(f"보고서 없음: {path}", file=sys.stderr)
        return 1

    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    total = sum(int(suite.get("tests", 0)) for suite in suites)
    skipped = sum(int(suite.get("skipped", 0)) for suite in suites)
    failures = sum(int(suite.get("failures", 0)) for suite in suites)
    errors = sum(int(suite.get("errors", 0)) for suite in suites)
    executed = total - skipped

    print(f"browser_tests total={total} executed={executed} skipped={skipped} "
          f"failures={failures} errors={errors}")
    if total == 0:
        print("브라우저 시험이 수집되지 않았다", file=sys.stderr)
        return 1
    if executed == 0:
        print("브라우저 시험이 실행되지 않았다 — 모두 건너뛰었다", file=sys.stderr)
        return 1
    if failures or errors:
        print("브라우저 시험이 실패했다", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
