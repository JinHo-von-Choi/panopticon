#!/usr/bin/env python3
"""출시 게이트 러너 (G0) — PR 01의 CI 계약.

게이트는 "맞았는지"가 아니라 "이 상태로 배포해도 되는지"를 판정한다.
그래서 각 게이트는 **반드시 통과해야 하는 검사**로만 구성한다. 통과로 오인될 수
있는 항목(예: 설정 검증이므로 차단 기능이 안전하다)은 검사 목록에 넣지 않는다.

사용법::

    # 전체 게이트 실행 (config/default.yaml 기준)
    python scripts/gates.py

    # 특정 게이트만
    python scripts/gates.py --gate G0

    # JSON 출력 (CI용)
    python scripts/gates.py --json

종료 코드: 모든 게이트 통과 0, 하나라도 실패 1.

작성자: 최진호
작성일: 2026-10-05
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# 로컬 .env 는 게이트 판정에서 제외한다.
#
# 이유: Config.load() 는 .env 를 자동으로 읽는다. 개발자 PC 에 로그인 설정이
# 들어 있으면 `config/default.yaml` 이 0.0.0.0 + 인증비활성 인데도 게이트가
# "위반 없음" 으로 통과한다. **같은 파일이 사람마다 다른 판정을 받는 것은
# 판정이 아니다.** 게이트는 배포되는 파일 그 자체를 심판해야 한다.
#
# 배포 환경에서 환경변수로 위반을 해소하는 것은 정상이며, 그렇게 하면 게이트는
# 그 위반을 보고하지 않는다. 하지만 그것은 배포자가 이미 조치한 뒤의 이야기다.
os.environ.setdefault("NETWATCHER_SKIP_DOTENV", "1")

DEFAULT_CONFIG = REPO_ROOT / "config" / "default.yaml"


@dataclass
class GateResult:
    """게이트 하나의 결과."""

    gate: str
    name: str
    passed: bool
    detail: str = ""
    checks: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "gate": self.gate,
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
            "checks": list(self.checks),
        }


# ------------------------------------------------------------------
# 게이트 정의
# ------------------------------------------------------------------

def gate_support_profile(config_path: Path) -> GateResult:
    """G0-1: 지원 프로필 계약을 만족해야 한다 (PR 01)."""
    from netwatcher.support import SupportContract
    from netwatcher.utils.config import Config

    if not config_path.exists():
        return GateResult("G0-1", "지원 프로필 계약", False, f"설정 파일 없음: {config_path}")

    contract = SupportContract(Config.load(config_path))
    violations = contract.violations()
    checks = [f"profile={contract.profile}", f"violations={len(violations)}"]
    if violations:
        return GateResult(
            "G0-1", "지원 프로필 계약", False,
            "; ".join(str(v) for v in violations), checks,
        )
    return GateResult("G0-1", "지원 프로필 계약", True, "", checks)


def gate_ai_write_isolation() -> GateResult:
    """G0-2: AI 제안 경로가 설정·런타임·방화벽을 바꾸지 않아야 한다 (PR 03)."""
    import ast

    path = REPO_ROOT / "netwatcher" / "services" / "ai_analyzer.py"
    if not path.exists():
        return GateResult("G0-2", "AI 쓰기 격리", False, f"파일 없음: {path}")

    tree = ast.parse(path.read_text(encoding="utf-8"))
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    forbidden = called & {"update_engine_config", "reload_engine", "block_ip", "add_block"}
    checks = [f"forbidden_calls={sorted(forbidden) or 'none'}"]
    if forbidden:
        return GateResult(
            "G0-2", "AI 쓰기 격리", False,
            f"제안 경로가 쓰기 호출을 포함한다: {sorted(forbidden)}", checks,
        )
    return GateResult("G0-2", "AI 쓰기 격리", True, "", checks)


def gate_safe_ui_output() -> GateResult:
    """G0-3: 대시보드가 실행 가능한 HTML/JS 를 렌더 경로에 만들지 않아야 한다 (PR 02)."""
    import re

    js_dir = REPO_ROOT / "netwatcher" / "web" / "static" / "js"
    if not js_dir.exists():
        return GateResult("G0-3", "안전한 UI 출력", False, f"정적 자산 없음: {js_dir}")

    pattern = re.compile(
        r"""on(?:click|change|submit|mouseover|focus|blur|load)\s*=\s*["'][^"']*\$\{""",
        re.IGNORECASE,
    )
    offenders: list[str] = []
    for js in sorted(js_dir.rglob("*.js")):
        for line_no, line in enumerate(js.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{js.relative_to(REPO_ROOT)}:{line_no}")

    checks = [f"offenders={len(offenders)}"]
    if offenders:
        return GateResult(
            "G0-3", "안전한 UI 출력", False,
            f"인라인 핸들더 내 템플릿 인터폴레이션: {offenders}", checks,
        )
    return GateResult("G0-3", "안전한 UI 출력", True, "", checks)


def gate_db_migrations() -> GateResult:
    """G0-4: 마이그레이션이 실제 DB 에 적용되어 있어야 한다.

    DB 가 없으면 '미검증'으로 보고 실패시킨다. 없는 DB 를 통과로 다루지 않기
    위한 의도적 선택이다.
    """
    versions_dir = REPO_ROOT / "alembic" / "versions"
    revisions = sorted(versions_dir.glob("*.py")) if versions_dir.exists() else []
    checks = [f"revisions={len(revisions)}"]
    if not revisions:
        return GateResult("G0-4", "DB 마이그레이션", False, "alembic 버전 없음", checks)

    try:
        import asyncpg  # noqa: F401
    except ImportError:
        return GateResult(
            "G0-4", "DB 마이그레이션", False,
            "asyncpg 미설치 — 마이그레이션 적용을 확인할 수 없다", checks,
        )

    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "current"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
    )
    checks.append("alembic_current=ok" if proc.returncode == 0 else "alembic_current=fail")
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()
        return GateResult(
            "G0-4", "DB 마이그레이션", False,
            f"`alembic current` 실패: {stderr[-1] if stderr else '알 수 없음'}", checks,
        )

    current = (proc.stdout or "").strip().splitlines()
    head = [line for line in current if "(head)" in line]
    checks.append("head_applied=yes" if head else "head_applied=no")
    if not head:
        return GateResult(
            "G0-4", "DB 마이그레이션", False,
            "마이그레이션 head 가 DB 에 적용되어 있지 않다 (`alembic upgrade head` 필요)", checks,
        )
    return GateResult("G0-4", "DB 마이그레이션", True, "", checks)


def gate_detection_contract() -> GateResult:
    """G0-7: 탐지 결과 계약(요약→근거→원자료)이 실제로 적용되어야 한다 (PR 08)."""
    ev = REPO_ROOT / "netwatcher" / "detection" / "evidence.py"
    disp = REPO_ROOT / "netwatcher" / "alerts" / "dispatcher.py"

    checks: list[str] = []
    if not ev.exists():
        return GateResult("G0-7", "탐지 결과 계약", False, f"파일 없음: {ev}")

    text = ev.read_text(encoding="utf-8")
    for required in ("def classify_alert", "def apply_evidence_contract"):
        present = required in text
        checks.append(f"{required}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-7", "탐지 결과 계약", False,
                f"{required} 가 없다 — 세 층(요약·근거·원자료) 판정이 없다", checks,
            )

    if disp.exists():
        dtext = disp.read_text(encoding="utf-8")
        applied = "apply_evidence_contract" in dtext
        checks.append(f"applied_in_dispatcher={'yes' if applied else 'no'}")
        if not applied:
            return GateResult(
                "G0-7", "탐지 결과 계약", False,
                "디스패처가 계약을 적용하지 않는다 — 판정이 있어도 실행되지 않는다", checks,
            )
    return GateResult("G0-7", "탐지 결과 계약", True, "", checks)


def gate_feed_lifecycle() -> GateResult:
    """G0-6: 위협 피드 생애주기 계약을 만족해야 한다 (PR 07).

    "갱신 루프가 살아 있다" 와 "지표가 최신이다" 를 구분하지 못하면,
    threat_intel 엔진이 조용히 아무것도 탐지하지 않는 상태를 놓친다.
    """
    path = REPO_ROOT / "netwatcher" / "threatintel" / "feed_manager.py"
    if not path.exists():
        return GateResult("G0-6", "위협 피드 생애주기", False, f"파일 없음: {path}")

    text = path.read_text(encoding="utf-8")
    checks: list[str] = []

    # 1) 갱신 전에 라이브 집합을 비우면 안 된다 (실패 시 지표가 사라짐)
    clears_live_state = "self._blocked_ips.clear()" in text
    checks.append(f"clears_live_state={'yes' if clears_live_state else 'no'}")
    if clears_live_state:
        return GateResult(
            "G0-6", "위협 피드 생애주기", False,
            "갱신 전에 라이브 차단 목록을 비운다 — 전체 실패 시 지표가 사라진다", checks,
        )

    # 2) 신선도 보고가 있어야 한다
    for required in ("def feed_health", "def is_stale", "health_as_violations"):
        present = required in text
        checks.append(f"{required}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-6", "위협 피드 생애주기", False,
                f"{required} 가 없다 — 피드 상태를 정직하게 보고할 수 없다", checks,
            )

    # 3) 갱신 루프가 기동 직후 첫 갱신을 해야 한다
    maint = REPO_ROOT / "netwatcher" / "services" / "maintenance.py"
    if maint.exists():
        mtext = maint.read_text(encoding="utf-8")
        loop = mtext[mtext.find("async def _feed_refresh_loop"):]
        loop = loop[:loop.find("\n    async def", 10)] if "\n    async def" in loop[10:] else loop
        sleeps_first = loop.strip().find("asyncio.sleep") < loop.find("update_all")
        checks.append(f"refresh_before_sleep={'yes' if not sleeps_first else 'no'}")
        if sleeps_first:
            return GateResult(
                "G0-6", "위협 피드 생애주기", False,
                "갱신 루프가 먼저 잠근다 — 기동 후 첫 갱신이 한 주기 밀린다", checks,
            )
    return GateResult("G0-6", "위협 피드 생애주기", True, "", checks)


def gate_approval_loop() -> GateResult:
    """G0-8: 승인 루프가 존재하고 승인이 유일한 쓰기 경로여야 한다 (PR 10).

    제안만 있고 승인 경로가 없으면 "승인" 은 장식이다. AI 제안이 갇히면
    되돌릴 방법 없이 로그로만 남는다.
    """
    svc = REPO_ROOT / "netwatcher" / "detection" / "proposals.py"
    route = REPO_ROOT / "netwatcher" / "web" / "routes" / "proposals.py"
    migrations = REPO_ROOT / "alembic" / "versions"

    checks: list[str] = []
    for path, label in ((svc, "service"), (route, "route")):
        if not path.exists():
            return GateResult("G0-8", "승인 루프", False, f"{label} 없음: {path}")

    stext = svc.read_text(encoding="utf-8")
    rtext = route.read_text(encoding="utf-8")

    # 1) 승인/거절 엔드포인트와 서비스가 모두 있어야 한다
    for required in ("async def decide", "async def submit"):
        present = required in stext
        checks.append(f"{required}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-8", "승인 루프", False, f"{required} 없음 — 승인 경로가 없다", checks,
            )
    for endpoint in ("/approve", "/reject"):
        present = endpoint in rtext
        checks.append(f"route{endpoint}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-8", "승인 루프", False, f"{endpoint} 엔드포인트 없음", checks,
            )

    # 2) 승인은 ADMIN 이어야 한다 (제안 권한과 분리)
    admin_guard = "require_role(Role.ADMIN)" in rtext
    checks.append(f"approve_requires_admin={'yes' if admin_guard else 'no'}")
    if not admin_guard:
        return GateResult(
            "G0-8", "승인 루프", False,
            "승인에 ADMIN 이 요구되지 않는다 — 역할 분리가 없다", checks,
        )

    # 3) 승인 시 재검증해야 한다 (접수 이후 설정이 바뀔 수 있다)
    revalidate = "validate_engine_config" in stext and stext.count("validate_engine_config") >= 2
    checks.append(f"revalidates_at_approval={'yes' if revalidate else 'no'}")
    if not revalidate:
        return GateResult(
            "G0-8", "승인 루프", False,
            "승인 시점에 검증하지 않는다 — 접수 후 변경이 통과한다", checks,
        )

    # 4) 저장 계층이 있어야 한다
    has_migration = any(
        "config_proposals" in p.read_text(encoding="utf-8")
        for p in migrations.glob("*.py")
    ) if migrations.exists() else False
    checks.append(f"storage={'yes' if has_migration else 'no'}")
    if not has_migration:
        return GateResult(
            "G0-8", "승인 루프", False,
            "config_proposals 마이그레이션이 없다 — 제안이 사라진다", checks,
        )
    return GateResult("G0-8", "승인 루프", True, "", checks)


def gate_observation_scope_ui() -> GateResult:
    """G0-9: 관측 범위와 승인 화면이 실제로 존재해야 한다 (PR 11).

    API 만 있고 화면이 없으면 "이 도구가 무엇을 하는지" 확인할 방법이 없고,
    승인하려면 curl 을 써야 한다. 계약이 대시보드에 닿지 않으면 장식이다.
    """
    static = REPO_ROOT / "netwatcher" / "web" / "static"
    gov = static / "js" / "modules" / "governance.js"
    index = static / "index.html"
    app_js = static / "js" / "app.js"
    css = static / "css" / "style.css"

    checks: list[str] = []
    for path, label in ((gov, "module"), (index, "html"), (app_js, "app"), (css, "css")):
        if not path.exists():
            return GateResult("G0-9", "관측 범위 화면", False, f"{label} 없음: {path}")

    gtext, itext, atext, ctext = (
        gov.read_text(encoding="utf-8"), index.read_text(encoding="utf-8"),
        app_js.read_text(encoding="utf-8"), css.read_text(encoding="utf-8"),
    )

    # 1) 탭과 라우팅
    for needle, where, label in (
        ('data-tab="governance"', itext, "html tab"),
        ('id="tab-governance"', itext, "html pane"),
        ("from './modules/governance.js'", atext, "app import"),
        ('target === "governance"', atext, "app routing"),
    ):
        present = needle in where
        checks.append(f"{label}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-9", "관측 범위 화면", False, f"{label} 없음 — 화면에 닿지 않는다", checks,
            )

    # 2) 지원 프로필 + 제안 승인 두 경로가 모두 있어야 한다
    for needle, label in (
        ("/api/support-profile", "support profile fetch"),
        ("/api/proposals", "proposal fetch"),
        ("승인", "approve action"),
        ("거절", "reject action"),
    ):
        present = needle in gtext
        checks.append(f"{label}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-9", "관측 범위 화면", False, f"{label} 없음", checks,
            )

    # 3) 위반/실패를 숨기지 않는지
    for needle, label in (
        ("운영 검증을 통과했다는 뜻이 아니다", "no enforcement overclaim"),
        ("승인됨 · 반영 실패", "failed apply surfaced"),
    ):
        present = needle in gtext
        checks.append(f"{label}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-9", "관측 범위 화면", False,
                f"{label} 없음 — 화면이 상태를 오인하게 한다", checks,
            )

    # 4) 안전한 출력 (G0-3 과 동일 기준)
    if re.search(r"""on(?:click|change|submit)\s*=\s*["'][^"']*\$\{""", gtext, re.IGNORECASE):
        return GateResult(
            "G0-9", "관측 범위 화면", False,
            "인라인 핸들러 내 템플릿 인터폴레이션 발견", checks,
        )
    return GateResult("G0-9", "관측 범위 화면", True, "", checks)


def gate_observation_contract() -> GateResult:
    """G0-10: 관측 범위 계약이 코드에 남아 있어야 한다 (계획서 3장).

    계측 모델만 있고 배선되지 않으면 계측값은 항상 0 이고, 그러면
    "관측됨" 이라는 판정은 아무것도 보지 않은 통과가 된다. 그래서

    1. 파이프라인 지점(캡처·입력 큐·엔진·결과 큐·DB)에 계측 호출이 있고
    2. 손실률이 커널 drop 과 앱 drop 을 합산하지 않으며
    3. 트래픽 0 이 장애로 판정되지 않는다

    를 함께 확인한다.
    """
    checks: list[str] = []
    obs = REPO_ROOT / "netwatcher" / "observability" / "observation.py"
    if not obs.exists():
        return GateResult("G0-10", "관측 범위 계약", False, f"파일 없음: {obs}")

    for path, label in (
        (REPO_ROOT / "netwatcher" / "web" / "routes" / "observation.py", "route"),
        (REPO_ROOT / "tests" / "test_observability" / "test_observation_scope.py", "contract test"),
        (REPO_ROOT / "tests" / "test_observability" / "test_observation_wiring.py", "wiring test"),
    ):
        if not path.exists():
            return GateResult("G0-10", "관측 범위 계약", False, f"{label} 없음: {path}")
    checks.append("files=yes")

    # 1) 계측 지점 배선 — 단계 상수가 실제 컴포넌트에 쓰여야 한다
    wiring = {
        "capture": REPO_ROOT / "netwatcher" / "capture" / "sniffer.py",
        "input_queue": REPO_ROOT / "netwatcher" / "capture" / "sniffer.py",
        "engine": REPO_ROOT / "netwatcher" / "services" / "packet_processor.py",
        "result_queue": REPO_ROOT / "netwatcher" / "alerts" / "dispatcher.py",
        "db": REPO_ROOT / "netwatcher" / "alerts" / "dispatcher.py",
    }
    for stage, path in wiring.items():
        text = path.read_text(encoding="utf-8")
        const = f"STAGE_{stage.upper()}" in text
        # 상수만 있고 호출이 없으면 계측 지점은 존재하지 않는다
        called = re.search(r"\.record\(\s*STAGE_" + stage.upper(), text) is not None
        present = const and called
        checks.append(
            f"stage:{stage}={'yes' if present else 'no'}"
            f"(const={'y' if const else 'n'},call={'y' if called else 'n'})"
        )
        if not present:
            return GateResult(
                "G0-10", "관측 범위 계약", False,
                f"{stage} 단계 계측 지점 없음 — 관측값이 항상 0 이 된다", checks,
            )

    otext = obs.read_text(encoding="utf-8")

    # 2) 손실률 규칙
    for needle, label in (
        ("app_loss_ratio", "loss ratio"),
        ("kernel_loss_note", "kernel not merged"),
        ("unknown_reason", "missing denominator"),
    ):
        present = needle in otext
        checks.append(f"{label}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-10", "관측 범위 계약", False,
                f"{label} 없음 — 손실률 규칙이 사라졌다", checks,
            )

    # 합산 금지: dropped_app 과 dropped_kernel 을 더하는 코드가 있으면 실패
    # 같은 식 안에서 두 식별자를 + 로 잇는 형태를 모두 잡는다
    if re.search(r"dropped_app[^\n]*\+[^\n]*dropped_kernel", otext):
        return GateResult(
            "G0-10", "관측 범위 계약", False,
            "커널 drop 과 앱 drop 을 더하는 코드가 있다", checks,
        )
    checks.append("no-merge=yes")

    # 3) 트래픽 0 은 장애가 아니다 — 문구로 고정
    if "장애로 판정하지 않는다" not in otext:
        return GateResult(
            "G0-10", "관측 범위 계약", False,
            "트래픽 0 을 장애로 다루지 않는다", checks,
        )
    checks.append("zero-traffic-not-outage=yes")

    # 4) API 는 이유 없는 상태를 내보내지 않는다
    route = (REPO_ROOT / "netwatcher" / "web" / "routes" / "observation.py").read_text(
        encoding="utf-8"
    )
    if "reasons" not in route:
        return GateResult(
            "G0-10", "관측 범위 계약", False, "판정 근거를 노출하지 않는다", checks,
        )
    checks.append("reasons-exposed=yes")

    return GateResult("G0-10", "관측 범위 계약", True, "", checks)


def gate_replay_isolation() -> GateResult:
    """G0-11: 리플레이는 운영 경로에 닿지 않아야 한다 (계획서 1장).

        "재실행은 운영 Dispatcher 를 호출하지 않는다. 저장 바이트→파서→
         순수 분석→격리 결과 저장만 허용하며 NIC 주입·외부 DNS/피드 조회·
         알림·방화벽·운영 DB 쓰기는 차단한다."

    이건 주석으로 보장할 수 없다. 주석은 약속이고 게이트는 사실이다.
    리플레이 패키지 전체를 정적으로 검사해 금지 참조가 0 인지 확인한다.
    """
    replay_dir = REPO_ROOT / "netwatcher" / "replay"
    if not replay_dir.exists():
        return GateResult("G0-11", "리플레이 격리", False, f"패키지 없음: {replay_dir}")

    sources = sorted(replay_dir.glob("*.py"))
    if not sources:
        return GateResult("G0-11", "리플레이 격리", False, "리플레이 소스가 없다")

    # 금지: 운영 경로로 나가는 모든 통로
    forbidden_modules = (
        "netwatcher.alerts", "netwatcher.response", "netwatcher.capture",
        "netwatcher.threatintel", "netwatcher.utils.network",
        "netwatcher.services", "scapy", "httpx", "socket", "requests",
    )
    # 금지: 운영 DB 테이블 (격리 저장은 replay_results 뿐)
    forbidden_sql = ("events", "alert_dispatch", "blocks", "custom_blocklist")
    # 금지: 운영 동작
    forbidden_calls = ("enqueue(", "init_chain(", "update_all(", "flush_observation(")

    checks: list[str] = []
    violations: list[str] = []

    for path in sources:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)

        # import 검사
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
                    if module.startswith(forbidden_modules):
                        violations.append(f"{path.name}: import {module}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
                if module.startswith(forbidden_modules):
                    violations.append(f"{path.name}: from {module} import ...")

        # 호출·SQL 검사
        for needle in forbidden_calls:
            if needle in text:
                violations.append(f"{path.name}: {needle}")
        for table in forbidden_sql:
            for match in re.finditer(
                rf"\b(?:INSERT\s+INTO|UPDATE|FROM)\s+{table}\b", text, re.IGNORECASE,
            ):
                violations.append(f"{path.name}: 운영 테이블 {table}")

    checks.append(f"files={len(sources)}")
    checks.append(f"forbidden_refs={len(violations)}")
    if violations:
        return GateResult(
            "G0-11", "리플레이 격리", False,
            "리플레이가 운영 경로에 닿는다:\n" + "\n".join(violations),
            checks,
        )
    checks.append("isolated=yes")

    # 격리 결과 테이블은 존재해야 한다 — 격리 저장은 되지만 말만 하지 않도록
    schemas = (REPO_ROOT / "netwatcher" / "storage" / "schemas.py").read_text(encoding="utf-8")
    if "REPLAY_RESULTS_TABLE" not in schemas or "replay_results" not in schemas:
        return GateResult(
            "G0-11", "리플레이 격리", False, "격리 결과 테이블이 없다", checks,
        )
    checks.append("isolated-store=yes")

    return GateResult("G0-11", "리플레이 격리", True, "", checks)


def _yaml_section(text: str, key: str) -> str:
    """YAML 의 최상위 섹션 하나만 정확히 잘라낸다.

    단순 ``split(key + ":")`` 로 하면 ``dns_response:`` 에서 잘린다. 섹션
    이름이 다른 키의 접미사일 수 있으므로 줄 단위로 판정한다.
    """
    lines = text.splitlines()
    out: list[str] = []
    inside = False
    base_indent = 0
    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if not inside:
            if stripped == f"{key}:":
                inside = True
                base_indent = indent
                out.append(line)
            continue
        if stripped and indent <= base_indent:
            break
        out.append(line)
    return "\n".join(out)


def gate_enforcement_honesty() -> GateResult:
    """G0-12: 강제를 주장하지 않는지 (계획서 2장).

        "최초 실제 적용은 Linux nftables 의 IPv4 input 전용 timeout set 을 새로
         구현하고 커널 측 만료를 검증한 경우에만 허용한다."
        "기존 iptables 자동 차단은 복구 검증 전 계속 비활성화한다."

    이 게이트는 **기능이 없음을 확인하는 게이트가 아니다.** PR 15 에서 실제
    백엔드를 구현했으므로, 대신 아래 불변식을 확인한다.

    1. 웹 계약 모듈(executor.py)은 OS 를 직접 건드리지 않는다
    2. OS 를 건드리는 백엔드는 별도 모듈이며 argv 만 쓴다 (셸 없음)
    3. 호스트의 iptables/ufw 테이블과 flush/delete rule 을 쓰지 않는다
    4. 커널 만료가 **실측** 으로만 참이 된다 (검증 진입점이 존재한다)
    5. 배포 설정이 자동 차단을 켜지 않는다
    """
    checks: list[str] = []
    executor = REPO_ROOT / "netwatcher" / "response" / "executor.py"
    nft = REPO_ROOT / "netwatcher" / "response" / "nftables_backend.py"
    routes = REPO_ROOT / "netwatcher" / "web" / "routes" / "response.py"
    verify_entry = REPO_ROOT / "netwatcher" / "verify_nftables.py"
    for path, label in ((executor, "executor"), (nft, "nftables"),
                        (routes, "routes"), (verify_entry, "verify entry")):
        if not path.exists():
            return GateResult("G0-12", "강제 주장 정직성", False, f"{label} 없음: {path}")
    checks.append("files=yes")

    etext, ntext, rtext = (
        executor.read_text(encoding="utf-8"),
        nft.read_text(encoding="utf-8"),
        routes.read_text(encoding="utf-8"),
    )

    # 1) 웹 계약 모듈은 OS 를 건드리지 않는다
    for forbidden in ("subprocess", "os.system", "Popen"):
        if forbidden in etext:
            return GateResult(
                "G0-12", "강제 주장 정직성", False,
                f"웹 계약 모듈이 OS 를 직접 조작한다: {forbidden}", checks,
            )
    checks.append("contract-no-os=yes")

    # 2) 실제 백엔드는 argv 만 쓴다 (셸 없음)
    if "shell=False" not in ntext:
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            "실제 백엔드가 셸 실행을 명시하지 않는다", checks,
        )
    if "shell=True" in ntext:
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            "실제 백엔드가 셸을 사용한다", checks,
        )
    checks.append("argv-only=yes")

    # 3) 호스트 방화벽을 건드리지 않는다.
    #    출처 정규식이 아니라 **실제로 생성되는 명령** 을 본다.
    #    (docstring 에 "ip filter 를 건드리지 않는다" 라고 쓰여 있는 것을
    #     위반으로 잡는 오탐을 피한다. 검사 대상이 코드가 아니라 출력이다.)
    try:
        from netwatcher.response import nftables_backend as nftmod
    except Exception as exc:  # pragma: no cover - import 실패는 게이트 실패
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            f"nftables 백엔드를 불러올 수 없다: {exc}", checks,
        )

    probe = "198.18.0.1"
    generated = [c.argv for c in nftmod.build_init_commands("gate:probe")]
    generated.append(nftmod.build_add_element_command(probe, 300).argv)
    generated.append(nftmod.build_delete_element_command(probe).argv)
    generated.append(nftmod.build_get_element_command(probe).argv)
    generated.append(nftmod.build_list_set_command().argv)

    for argv in generated:
        joined = " ".join(argv)
        if re.search(r"\bip\s+filter\b", joined):
            return GateResult(
                "G0-12", "강제 주장 정직성", False,
                f"생성된 명령이 호스트 테이블을 가리킨다: {joined}", checks,
            )
        if "flush" in joined.lower():
            return GateResult(
                "G0-12", "강제 주장 정직성", False,
                f"생성된 명령이 flush 다: {joined}", checks,
            )
        if re.search(r"\bdelete\s+rule\b", joined):
            return GateResult(
                "G0-12", "강제 주장 정직성", False,
                f"생성된 명령이 타 규칙을 지운다: {joined}", checks,
            )
        if f"{nftmod.TABLE_FAMILY} {nftmod.TABLE_NAME}" not in joined \
                and joined.split()[0] in ("add", "delete", "get", "list"):
            if f"{nftmod.TABLE_FAMILY}" not in joined:
                return GateResult(
                    "G0-12", "강제 주장 정직성", False,
                    f"우리 소유 테이블 밖을 가리킨다: {joined}", checks,
                )
    checks.append(f"host-firewall-untouched=yes({len(generated)}cmds)")

    # 조회 확인이 실제 제거로 번지지 않는지도 본다
    if nftmod.build_get_element_command(probe).argv[0] != "get":
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            "조회 명령이 조회가 아니다", checks,
        )

    # 4) 만료는 실측으로만 참이 된다
    if "probe_kernel_expiry" not in ntext:
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            "커널 만료 검증 경로가 없다", checks,
        )
    checks.append("expiry-probe=yes")

    # 5) 배포 설정은 자동 차단을 켜지 않는다
    cfg = (REPO_ROOT / "config" / "default.yaml").read_text(encoding="utf-8")
    response_section = _yaml_section(cfg, "response")
    if not response_section:
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            "설정에서 response 섹션을 찾지 못했다", checks,
        )
    if re.search(r"^\s*enabled:\s*true", response_section, re.MULTILINE):
        return GateResult(
            "G0-12", "강제 주장 정직성", False,
            "response.enabled 가 true 다 — 복구 검증 전 자동 차단은 비활성이다", checks,
        )
    checks.append("auto-block-disabled=yes")

    # 6) 미확인/재승인/멱등 경로가 남아 있어야 한다
    for needle, label in (
        ("unknown", "unknown 상태"),
        ("재승인이 필요합니다", "approve/activate 불일치"),
        ("idempotency", "멱등성"),
    ):
        if needle not in rtext:
            return GateResult(
                "G0-12", "강제 주장 정직성", False, f"{label} 경로가 없다", checks,
            )
    checks.append("contracts-present=yes")

    return GateResult("G0-12", "강제 주장 정직성", True, "", checks)


def _migration_upgrade_body(text: str) -> str:
    """마이그레이션 파일의 upgrade() 본문만 돌려준다.

    downgrade() 의 DROP TABLE 을 섞으면 모든 테이블이 "일시적" 으로 보인다.
    """
    start = text.find("def upgrade(")
    if start == -1:
        return text
    end = text.find("def downgrade(", start)
    return text[start:end] if end != -1 else text[start:]


def gate_schema_parity() -> GateResult:
    """G0-13: 마이그레이션과 스키마 정의를 대조한다.

    테스트 DB 는 마이그레이션이 아니라 `storage/schemas.py` 의 `ALL_SCHEMAS`
    로 만들어진다. 그래서 마이그레이션에 테이블을 추가하고 `ALL_SCHEMAS` 를
    빠뜨리면 **테스트는 통과하는데 그 테이블이 없다** — 코드가 돌아가지 않는
    상태를 통과로 보고하는 가장 나쁜 종류의 불일치다.

    실제로 세 번 발생했다. 주석으로 막을 수 없어 게이트로 막는다.
    """
    from netwatcher.storage import schemas as schema_module

    versions = sorted((REPO_ROOT / "alembic" / "versions").glob("*.py"))
    declared = set()
    for path in versions:
        upgrade_body = _migration_upgrade_body(path.read_text(encoding="utf-8"))
        created = {
            m.lower() for m in re.findall(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\S*\s+EXISTS\s+|AS\s+SELECT\s+\*\s+FROM\s+\w+\s+AS\s+)?(\w+)?",
                upgrade_body, re.IGNORECASE,
            )
            if m
        }
        # **upgrade 안에서** 생성되고 **upgrade 안에서** 사라지는 테이블은
        # 일시적 작업 테이블이다 (008 의 events_backup 처럼). 마이그레이션이
        # 끝나면 존재하지 않으므로 스키마 정의를 기대하면 안 된다.
        # downgrade 의 DROP 는 여기서 보지 않는다 — 그러면 전부 잠시것이 된다.
        transient = {
            m.lower() for m in re.findall(
                r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)",
                upgrade_body, re.IGNORECASE,
            )
        }
        declared |= created - transient

    # alembic 이 관리하는 테이블은 우리가 만들지 않는다
    declared -= {"alembic_version"}

    all_schemas = " ".join(schema_module.ALL_SCHEMAS).lower()
    missing = sorted(t for t in declared if t not in all_schemas)

    checks = [
        f"migrations={len(versions)}",
        f"tables={len(declared)}",
        f"missing={len(missing)}",
    ]
    if missing:
        return GateResult(
            "G0-13", "스키마 정합성", False,
            "마이그레이션에 있지만 ALL_SCHEMAS 에 없는 테이블:\n  "
            + "\n  ".join(missing)
            + "\n테스트 DB 는 마이그레이션이 아니라 ALL_SCHEMAS 로 만들어진다.",
            checks,
        )
    checks.append("parity=yes")
    return GateResult("G0-13", "스키마 정합성", True, "", checks)


def gate_tests() -> GateResult:
    """G0-5: 회귀 스위트가 통과해야 한다."""
    cmd = [sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=3600)
    tail = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()][-1:]
    summary = tail[0] if tail else ""
    checks = [summary or "no output"]
    if proc.returncode != 0:
        return GateResult("G0-5", "회귀 스위트", False, summary, checks)
    return GateResult("G0-5", "회귀 스위트", True, "", checks)


GATES: tuple[Callable[..., GateResult], ...] = (
    gate_support_profile,
    gate_ai_write_isolation,
    gate_safe_ui_output,
    gate_db_migrations,
    gate_feed_lifecycle,
    gate_detection_contract,
    gate_approval_loop,
    gate_observation_scope_ui,
    gate_observation_contract,
    gate_replay_isolation,
    gate_enforcement_honesty,
    gate_schema_parity,
    gate_tests,
)

# 게이트 번호 → 함수 매핑 (--gate 인자용)
GATE_BY_ID = {
    "G0-1": gate_support_profile,
    "G0-2": gate_ai_write_isolation,
    "G0-3": gate_safe_ui_output,
    "G0-4": gate_db_migrations,
    "G0-6": gate_feed_lifecycle,
    "G0-7": gate_detection_contract,
    "G0-8": gate_approval_loop,
    "G0-9": gate_observation_scope_ui,
    "G0-10": gate_observation_contract,
    "G0-11": gate_replay_isolation,
    "G0-12": gate_enforcement_honesty,
    "G0-13": gate_schema_parity,
    "G0-5": gate_tests,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NetWatcher 출시 게이트 러너 (G0)")
    parser.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG,
                        help="검증할 설정 파일 (기본: config/default.yaml)")
    parser.add_argument("--gate", action="append", choices=sorted(GATE_BY_ID),
                        help="특정 게이트만 실행 (반복 가능)")
    parser.add_argument("--json", action="store_true", help="JSON 형식으로 출력")
    args = parser.parse_args(argv)

    selected = [GATE_BY_ID[g] for g in args.gate] if args.gate else list(GATES)

    results: list[GateResult] = []
    for gate in selected:
        # 설정 파일을 받는 게이트만 인자를 넘긴다
        if gate.__code__.co_argcount > 0:
            result = gate(args.config)
        else:
            result = gate()
        results.append(result)

    if args.json:
        print(json.dumps(
            {"passed": all(r.passed for r in results), "gates": [r.as_dict() for r in results]},
            ensure_ascii=False, indent=2,
        ))
    else:
        for r in results:
            mark = "PASS" if r.passed else "FAIL"
            print(f"[{mark}] {r.gate} {r.name}")
            for check in r.checks:
                print(f"         {check}")
            if not r.passed:
                for line in r.detail.splitlines():
                    print(f"         {line}")
        total = len(results)
        passed = sum(1 for r in results if r.passed)
        print(f"\n{passed}/{total} 게이트 통과")

    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
