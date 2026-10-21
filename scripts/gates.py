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
import tempfile
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


# ------------------------------------------------------------------
# 구조 검사 도구 — 문자열 존재 검사 대신 코드를 해석한다
# ------------------------------------------------------------------

def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _defined_functions(tree: ast.Module) -> set[str]:
    """정의된 함수 이름."""
    return {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _call_name(node: ast.Call) -> str | None:
    """호출 이름. 속성 호출이면 속성 이름을 준다."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _calls_to(tree: ast.Module, name: str) -> list[ast.Call]:
    """이름으로 호출된 지점들."""
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == name
    ]


def _clears_attribute(tree: ast.Module, attribute: str) -> bool:
    """self.<attribute>.clear() 호출이 있는지."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "clear":
            continue
        value = func.value
        if isinstance(value, ast.Attribute) and value.attr == attribute:
            return True
    return False


def _route_paths(tree: ast.Module) -> set[str]:
    """라우트 데코레이터가 붙은 경로들."""
    paths: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if not isinstance(target, ast.Attribute):
                continue
            if target.attr not in {"get", "post", "put", "patch", "delete"}:
                continue
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                value = decorator.args[0].value
                if isinstance(value, str):
                    paths.add(value)
    return paths


def _requires_admin(tree: ast.Module) -> bool:
    """require_role(Role.ADMIN) 호출이 있는지."""
    for node in _calls_to(tree, "require_role"):
        for argument in node.args:
            if isinstance(argument, ast.Attribute) and argument.attr == "ADMIN":
                return True
    return False


def _function_body(tree: ast.Module, name: str) -> ast.AST | None:
    """이름이 붙은 함수의 본문."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _first_call_position(function: ast.AST, name: str) -> int | None:
    """함수 본문에서 해당 호출이 처음 나오는 줄."""
    best: int | None = None
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and _call_name(node) == name:
            if best is None or node.lineno < best:
                best = node.lineno
    return best


def _strip_comments(text: str, language: str = "js") -> str:
    """주석을 지운다 — 주석에 적힌 문자열로 검사를 통과시키지 못하게 한다."""
    if language == "html":
        return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(?m)^\s*//.*$", "", text)


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


def yaml_write_surface() -> set[str]:
    """설정을 바꾸는 공개 표면을 자동으로 모은다.

    금지 목록을 하드코딩하면 새 쓰기 메서드가 늘 때마다 목록을 잊는다.
    그래서 설정 편집기와 엔진 재적용·차단 적용의 공개 메서드를 직접 훑는다.
    """
    import inspect

    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.response.blocker import BlockManager
    from netwatcher.utils.yaml_editor import YamlConfigEditor

    def public(cls) -> set[str]:
        return {
            name for name, member in inspect.getmembers(cls, inspect.isfunction)
            if not name.startswith("_")
        }

    surface = public(YamlConfigEditor) | public(EngineRegistry) | public(BlockManager)
    return {name for name in surface if name.startswith(
        ("update_", "set_", "write_", "save_", "delete_", "remove_", "add_", "block_", "reload_")
    )}


def gate_ai_write_isolation() -> GateResult:
    """G0-2: AI 제안 경로가 설정·런타임·방화벽을 바꾸지 않아야 한다 (PR 03)."""
    import ast

    path = REPO_ROOT / "netwatcher" / "services" / "ai_analyzer.py"
    if not path.exists():
        return GateResult("G0-2", "AI 쓰기 격리", False, f"파일 없음: {path}")

    # 분석기와 공급자 계층 모두 같은 금지 호출 검사를 받는다.
    paths = [path, *sorted((REPO_ROOT / "netwatcher" / "ai").glob("*.py"))]
    forbidden_surface = yaml_write_surface()
    called: set[str] = set()
    imported_calls: set[str] = set()
    for source in paths:
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                # "from x import write_fn" 형태는 속성 호출이 아니라 이름 호출이다.
                if node.func.id in imported:
                    imported_calls.add(node.func.id)
    forbidden = (called | imported_calls) & forbidden_surface
    checks = [
        f"files={len(paths)}",
        f"surface={len(forbidden_surface)}",
        f"forbidden_calls={sorted(forbidden) or 'none'}",
    ]
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

    defined = _defined_functions(_tree(ev))
    for required in ("classify_alert", "apply_evidence_contract"):
        present = required in defined
        checks.append(f"{required}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-7", "탐지 결과 계약", False,
                f"{required} 가 없다 — 세 층(요약·근고·원자료) 판정이 없다", checks,
            )

    if disp.exists():
        applied = bool(_calls_to(_tree(disp), "apply_evidence_contract"))
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

    tree = _tree(path)
    checks: list[str] = []

    # 1) 갱신 전에 라이브 집합을 비우면 안 된다 (실패 시 지표가 사라짐)
    clears_live_state = _clears_attribute(tree, "_blocked_ips")
    checks.append(f"clears_live_state={'yes' if clears_live_state else 'no'}")
    if clears_live_state:
        return GateResult(
            "G0-6", "위협 피드 생애주기", False,
            "갱신 전에 라이브 차단 목록을 비운다 — 전체 실패 시 지표가 사라진다", checks,
        )

    # 2) 신선도 보고가 있어야 한다
    defined = _defined_functions(tree)
    for required in ("feed_health", "is_stale"):
        present = required in defined
        checks.append(f"{required}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-6", "위협 피드 생애주기", False,
                f"{required} 가 없다 — 피드 상태를 정직하게 보고할 수 없다", checks,
            )
    reported = "health_as_violations" in defined
    if reported:
        # 정의만으로는 충분하지 않다 — 상태를 실제로 보고하는 곳이 있어야 한다.
        server = REPO_ROOT / "netwatcher" / "web" / "server.py"
        reported = server.exists() and bool(_calls_to(_tree(server), "health_as_violations"))
    checks.append(f"health_as_violations={'yes' if reported else 'no'}")
    if not reported:
        return GateResult(
            "G0-6", "위협 피드 생애주기", False,
            "health_as_violations 가 정의만 되고 호출되지 않는다 — 피드 상태를 위반으로 보고할 수 없다",
            checks,
        )

    # 3) 갱신 루프가 기동 직후 첫 갱신을 해야 한다
    maint = REPO_ROOT / "netwatcher" / "services" / "maintenance.py"
    if maint.exists():
        loop = _function_body(_tree(maint), "_feed_refresh_loop")
        if loop is not None:
            sleep_at = _first_call_position(loop, "sleep")
            update_at = _first_call_position(loop, "update_all")
            sleeps_first = sleep_at is not None and update_at is not None and sleep_at < update_at
            checks.append(f"refresh_before_sleep={'yes' if not sleeps_first else 'no'}")
            if sleeps_first:
                return GateResult(
                    "G0-6", "위협 피드 생애주기", False,
                    "갱신 루프가 먼저 잠근다 — 기동 후 첫 갱신이 한 주기 밀린다", checks,
                )
    return GateResult("G0-6", "위협 피드 생애주기", True, "", checks)


def gate_approval_loop() -> GateResult:
    """G0-8: 승인 루프가 존재하고 승인이 유일한 쓰기 경로여야 한다 (PR 10).

    제안만 있고 승인 경로가 없으면 "승인" 은 장식이다. AI 제안이 갱히면
    되돌릴 방법 없이 로그로만 남는다.
    """
    svc = REPO_ROOT / "netwatcher" / "detection" / "proposals.py"
    route = REPO_ROOT / "netwatcher" / "web" / "routes" / "proposals.py"
    migrations = REPO_ROOT / "alembic" / "versions"

    checks: list[str] = []
    for path, label in ((svc, "service"), (route, "route")):
        if not path.exists():
            return GateResult("G0-8", "승인 루프", False, f"{label} 없음: {path}")

    service_tree = _tree(svc)
    route_tree = _tree(route)

    # 1) 승인/거절 엔드포인트와 서비스가 모두 있어야 한다
    defined = _defined_functions(service_tree)
    for required in ("decide", "submit"):
        present = required in defined
        checks.append(f"def {required}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-8", "승인 루프", False, f"{required} 없음 — 승인 경로가 없다", checks,
            )
    paths = _route_paths(route_tree)
    for endpoint in ("/approve", "/reject"):
        present = any(endpoint in path for path in paths)
        checks.append(f"route{endpoint}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-8", "승인 루프", False, f"{endpoint} 엔드포인트 없음", checks,
            )

    # 2) 승인은 ADMIN 이어야 한다 (제안 권한과 분리)
    admin_guard = _requires_admin(route_tree)
    checks.append(f"approve_requires_admin={'yes' if admin_guard else 'no'}")
    if not admin_guard:
        return GateResult(
            "G0-8", "승인 루프", False,
            "승인에 ADMIN 이 요구되지 않는다 — 역할 분리가 없다", checks,
        )

    # 3) 승인 시 재검증해야 한다 (접수 이후 설정이 바뀔 수 있다)
    revalidations = len(_calls_to(service_tree, "validate_engine_config"))
    revalidate = revalidations >= 2
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
        _strip_comments(gov.read_text(encoding="utf-8")),
        _strip_comments(index.read_text(encoding="utf-8"), "html"),
        _strip_comments(app_js.read_text(encoding="utf-8")),
        _strip_comments(css.read_text(encoding="utf-8")),
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

    ):
        present = needle in gtext
        checks.append(f"{label}={'yes' if present else 'no'}")
        if not present:
            return GateResult(
                "G0-9", "관측 범위 화면", False,
                f"{label} 없음 — 화면이 상태를 오인하게 한다", checks,
            )

    failure_display = "승인됨 · 반영 실패" in gtext
    if "tp('apply_failed')" in gtext:
        failure_display = True
        for language in ('ko', 'en'):
            try:
                messages = json.loads((REPO_ROOT / 'netwatcher/web/static/locales' / language / 'translation.json').read_text())
                failure_display = failure_display and bool(messages['console']['proposals']['apply_failed'])
            except (OSError, ValueError, KeyError):
                failure_display = False
    failure_display = failure_display and 'proposal-failed' in gtext and 'data.status === "failed"' in gtext
    checks.append(f"failed apply surfaced={'yes' if failure_display else 'no'}")
    if not failure_display:
        return GateResult('G0-9', '관측 범위 화면', False, 'Failed apply state or localized display missing', checks)

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
    # 마이그레이션 체인을 순서대로 따라가 **head 에 남아 있는** 테이블을
    # 구한다. 나중에 폐기된 테이블(044 의 users 같은 것)을 요구하면
    # 존재하지 않는 스키마를 기다리는 게 된다.
    existing: set[str] = set()
    for path in versions:
        upgrade_body = _migration_upgrade_body(path.read_text(encoding="utf-8"))
        created = {
            m.lower() for m in re.findall(
                r"CREATE\s+TABLE\s+(?:IF\s+NOT\S*\s+EXISTS\s+|AS\s+SELECT\s+\*\s+FROM\s+\w+\s+AS\s+)?(\w+)?",
                upgrade_body, re.IGNORECASE,
            )
            if m
        }
        # 같은 upgrade 안에서 사라지는 테이블은 일시적 작업 테이블이다
        # (008 의 events_backup 처럼).
        transient = {
            m.lower() for m in re.findall(
                r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)",
                upgrade_body, re.IGNORECASE,
            )
        }
        existing |= created - transient
        existing -= transient - created
    declared = existing

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


def gate_static_analysis() -> GateResult:
    """G0-15: 정적 분석 기준선이 깨지지 않아야 한다.

    이 저장소에는 오랫동안 린터가 없었다. pyproject.toml 의 ruff 설정이
    항상 켜는 규칙(E9 문법, F401 미사용 임포트, F541 무의미 f-string)을
    강제한다. 여기에 도입 시점에 남아 있던 부채는 카운트 상한으로 묶어,
    **늘어날 수만 없게** 했다. 하나를 고칠 때마다 상한을 낮춘다.
    """
    debt_rules = "B904,B007,F841,B905,B023,B015"
    budget = {"B904": 12, "B007": 10, "F841": 8, "B905": 8, "B023": 1, "B015": 1}
    checks: list[str] = []

    proc = subprocess.run([sys.executable, "-m", "ruff", "check", "netwatcher/", "scripts/", "tests/"],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        return GateResult("G0-15", "정적 분석", False,
                          (proc.stdout or proc.stderr or "").strip()[-400:], checks)
    checks.append("ruff-check=clean")

    # --isolated 가 필수다. pyproject.toml 의 ignore 목록이 --select 를 덮어써서,
    # 없으면 상한을 잴 대상이 통째로 사라지고 게이트가 "0건"을 보고한다.
    # 부채가 없다고 믿게 만드는 게이트는 없는 것보다 나쁘다.
    proc = subprocess.run([sys.executable, "-m", "ruff", "check", "--isolated",
                           "--select", debt_rules, "--statistics",
                           "netwatcher/", "scripts/", "tests/"],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=300)
    counts: dict[str, int] = {}
    for line in (proc.stdout or "").splitlines():
        # ruff --statistics 는 "개수<TAB>규칙ID<TAB>설명" 순서다.
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isupper():
            counts[parts[1]] = int(parts[0])
    grown = [f"{rule} {counts.get(rule, 0)}/{limit}" for rule, limit in budget.items()
             if counts.get(rule, 0) > limit]
    slack = [f"{rule} {counts.get(rule, 0)}/{limit}" for rule, limit in budget.items()
             if counts.get(rule, 0) < limit]
    checks.append("debt=" + ",".join(f"{r}:{counts.get(r, 0)}/{l}" for r, l in budget.items()))
    if grown:
        return GateResult("G0-15", "정적 분석", False,
                          "정적 분석 부채 상한 초과: " + ", ".join(grown), checks)
    if slack:
        # 상한이 실제보다 크면 빚을 갚았다고 말할 수 없다. 상한을 실제
        # 카운트에 맞춰 내리고, 0 이 되면 그 규칙은 상시 켠다.
        return GateResult("G0-15", "정적 분석", False,
                          "정적 분석 부채 상한이 실제보다 크다 (상환 필요): "
                          + ", ".join(slack), checks)
    return GateResult("G0-15", "정적 분석", True, "", checks)


def gate_tests() -> GateResult:
    """G0-5: 회귀 스위트가 통과해야 하고, 커버리지가 떨어지지 않아야 한다.

    처리량 측정은 계측(instrumentation) 의 영향을 받는다 — 계측된 실행은
    실제보다 느리다. 그래서 성능 시험은 커버리지 측정 밖에서 돌리고, 그
    결과로 코드 회귀를 판정한다.
    """
    checks: list[str] = []
    cmd = [
        sys.executable, "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider",
        "--cov=netwatcher", "--cov-report=term",
        "--deselect", "tests/test_performance/test_throughput.py",
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=5400)
    tail = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    summary = ""
    for line in reversed(tail):
        if "passed" in line or "failed" in line:
            summary = line.strip()
            break
    checks.append(summary or "no output")
    if proc.returncode != 0:
        # 요약만 남기면 실패한 시험을 찾기 위해 전체 스위트를 다시 돌려야 한다.
        fd, report_path = tempfile.mkstemp(prefix="panopticon-regression-", suffix=".log")
        with os.fdopen(fd, "w", encoding="utf-8") as report:
            report.write(proc.stdout or "")
            report.write(proc.stderr or "")
        failures = [line for line in (proc.stdout or "").splitlines() if line.startswith("FAILED ")]
        checks.append(f"failure-report={report_path}")
        return GateResult("G0-5", "회귀 스위트", False, "\n".join(failures) or summary, checks)

    total = [line for line in tail if line.strip().startswith("TOTAL")]
    checks.append(total[-1].strip() if total else "coverage=unknown")

    perf = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_performance/test_throughput.py",
         "-q", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=1800,
    )
    checks.append("performance=run")
    if perf.returncode != 0:
        failures = [line for line in (perf.stdout or "").splitlines() if line.startswith("FAILED ")]
        return GateResult(
            "G0-5", "회귀 스위트", False,
            "처리량 측정 실패: " + ("\n".join(failures) or "실패 요약 없음"), checks,
        )
    return GateResult("G0-5", "회귀 스위트", True, "", checks)


# 본문 자격증명으로 인증되는 변경 경로. 예외로 기록한다 — 열거 예외이므로
# 다른 경로를 숨기지 않는다.
BODY_CREDENTIAL_PATHS = ("/api/agent/enroll",)


def missing_admin_guards(routes) -> list[str]:
    """등록된 변경 경로의 실제 FastAPI 의존성 그래프를 검사한다."""
    from netwatcher.web.rbac import Role, is_admin_change

    def guarded(dependant):
        for dependency in dependant.dependencies:
            call = dependency.call
            if (getattr(call, "__module__", None) == "netwatcher.web.rbac"
                    and getattr(call, "required_roles", None) == (Role.ADMIN,)):
                return True
            if guarded(dependency):
                return True
        return False

    missing = []
    for route in routes:
        for method in getattr(route, "methods", ()):
            if is_admin_change(route.path, method) and not guarded(route.dependant):
                missing.append(f"{method} {route.path}")
    return sorted(missing)


def unguarded_mutations(routes) -> list[str]:
    """권한 검사 자체가 없는 변경 경로를 모두 찾는다.

    관리자 변경 목록은 하드코딩이라 새 접두 경로를 놓친다. 그래서
    목록과 무관하게 **어떤 변경 경로든** 접근 검사가 있어야 한다.
    로그인 경로는 원래 공개 경로라 제외한다.
    """
    from netwatcher.web.rbac import MUTATION_METHODS

    def has_access_check(dependant):
        for dependency in dependant.dependencies:
            call = dependency.call
            # 역할 검사(rbac)든 기기 토큰 검사든, 호출 가능한 의존성이 있으면
            # 그 경로에는 접근 검사가 걸려 있다.
            if callable(call) and not isinstance(call, type):
                return True
            if has_access_check(dependency):
                return True
        return False

    missing = []
    for route in routes:
        path = getattr(route, "path", "")
        if path.startswith("/api/auth/"):
            continue
        if path in BODY_CREDENTIAL_PATHS:
            continue
        for method in getattr(route, "methods", ()):
            if method in MUTATION_METHODS and not has_access_check(route.dependant):
                missing.append(f"{method} {path}")
    return sorted(missing)


def gate_mutation_permissions() -> GateResult:
    """G0-14: 관리자 변경 경로에 명시적 권한 의존성이 있어야 한다."""
    from unittest.mock import MagicMock
    from netwatcher.utils.config import Config
    from netwatcher.web.server import create_app

    app = create_app(Config({}), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
                     block_manager=MagicMock(), blocklist_repo=MagicMock(),
                     feed_manager=MagicMock(), whitelist=MagicMock(),
                     signature_engine=MagicMock(), registry=MagicMock(), yaml_editor=MagicMock(),
                     incident_repository=MagicMock())
    missing = missing_admin_guards(app.routes)
    # 응답·제안·리플레이·관측 경로까지 포함한다 — 이전에는 이 라우터들이
    # 게이트 대상에서 빠져 있었다.
    extended = create_app(
        Config({}), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
        block_manager=MagicMock(), blocklist_repo=MagicMock(),
        feed_manager=MagicMock(), whitelist=MagicMock(),
        signature_engine=MagicMock(), registry=MagicMock(), yaml_editor=MagicMock(),
        incident_repository=MagicMock(),
        response_repository=MagicMock(), response_executor=MagicMock(),
        response_proposal_repo=MagicMock(), replay_service=MagicMock(),
        observation_service=MagicMock(), kernel_probe=MagicMock(),
    )
    missing.extend(missing_admin_guards(extended.routes))
    unguarded = unguarded_mutations(app.routes) + unguarded_mutations(extended.routes)
    managed = MagicMock()
    managed.enabled = True
    managed.multi_user = True
    managed.users = MagicMock()
    remote_app = create_app(Config({"input": {"mode": "native"}}), MagicMock(), MagicMock(), MagicMock(), MagicMock(),
                            auth_manager=managed, audit_logger=MagicMock(), audit_required=True,
                            sensor_control=MagicMock())
    missing.extend(missing_admin_guards(remote_app.routes))
    unguarded.extend(unguarded_mutations(remote_app.routes))
    checks = [
        f"missing={len(missing)}",
        f"unguarded={len(unguarded)}",
        "engine_profiles=local,remote,extended",
    ]
    problems = []
    if missing:
        problems.append("관리자 권한 누락: " + ", ".join(sorted(set(missing))))
    if unguarded:
        problems.append("권한 검사 없는 변경 경로: " + ", ".join(sorted(set(unguarded))))
    return GateResult("G0-14", "변경 라우트 권한", not problems,
                      " / ".join(problems), checks)


def gate_event_partitions() -> GateResult:
    """G0-16: events 월별 파티션이 확보되어 있어야 한다.

    파티션이 없으면 해당 월의 INSERT 가 실패해 경보 저장이 중단된다.
    게이트는 DB 를 고치지 않는다 — 상태만 확인하고 부족하면 실패시킨다.
    """
    checks: list[str] = []
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "netwatcher.storage.partition_manager", "--months", "3"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return GateResult(
            "G0-16", "events 월별 파티션", False,
            f"파티션 상태를 확인할 수 없다: {type(exc).__name__}: {exc}", checks,
        )

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()
        return GateResult(
            "G0-16", "events 월별 파티션", False,
            f"이번 달 파티션이 확보되지 않았다: {stderr[-1] if stderr else '알 수 없음'}", checks,
        )

    try:
        state = json.loads((proc.stdout or "").strip() or "{}")
    except json.JSONDecodeError as exc:
        return GateResult(
            "G0-16", "events 월별 파티션", False,
            f"파티션 상태 출력을 해석할 수 없다: {exc}", checks,
        )

    checks.append(f"partitioned={state.get('partitioned')}")
    checks.append(f"covered={state.get('covered')}")
    checks.append(f"current_month={state.get('current_month')}")
    missing = state.get("missing") or []
    checks.append(f"missing={len(missing)}")

    if not state.get("partitioned"):
        return GateResult(
            "G0-16", "events 월별 파티션", False,
            "events 테이블이 파티셔닝되어 있지 않다 "
            "(008_events_monthly_partitioning 마이그레이션 확인)", checks,
        )
    if not state.get("covered"):
        return GateResult(
            "G0-16", "events 월별 파티션", False,
            f"이번 달 파티션({state.get('current_month')})이 없다 — "
            "'python -m netwatcher.storage.partition_manager --ensure' 필요", checks,
        )
    if missing:
        checks.append(f"upcoming_missing={','.join(missing)}")
    return GateResult("G0-16", "events 월별 파티션", True, "", checks)


def gate_prompt_components() -> GateResult:
    """G0-17: 분석 프롬프트가 파일 단위 컴포넌트 계약을 지켜야 한다.

    프롬프트가 코드 안 문자열로 돌아가면 무엇이 바뀌었는지 비교할 수 없고
    출력 형식 계약도 검사할 수 없다. 컴포넌트 파일이 유효한지, 조립이
    파일에서 일어나는지를 함께 확인한다.
    """
    from netwatcher.ai.components import COMPONENT_ORDER, PromptTree, validate

    checks: list[str] = []
    try:
        tree = PromptTree.load()
    except Exception as exc:
        return GateResult(
            "G0-17", "프롬프트 컴포넌트", False,
            f"프롬프트 컴포넌트를 읽을 수 없다: {type(exc).__name__}: {exc}", checks,
        )

    problems = validate(tree)
    checks.append(f"components={len(COMPONENT_ORDER)}")
    checks.append(f"problems={len(problems)}")
    if problems:
        return GateResult(
            "G0-17", "프롬프트 컴포넌트", False,
            "프롬프트 컴포넌트 계약 위반:\n  " + "\n  ".join(problems), checks,
        )

    # 조립이 코드 안 문자열로 돌아가면 파일 계약이 무의미해진다.
    source = (REPO_ROOT / "netwatcher" / "services" / "ai_analyzer.py").read_text(encoding="utf-8")
    tree_ = ast.parse(source)
    literals: list[str] = []
    for node in ast.walk(tree_):
        if not isinstance(node, ast.FunctionDef) or node.name != "_build_prompt":
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                literals.append(child.value)
    longest = max((len(text) for text in literals), default=0)
    checks.append(f"longest_prompt_literal={longest}")
    if longest > 200:
        return GateResult(
            "G0-17", "프롬프트 컴포넌트", False,
            f"_build_prompt() 에 {longest} 글자짜리 문자열이 남아 있다 — "
            "프롬프트는 컴포넌트 파일에서 조립해야 한다", checks,
        )
    checks.append("assembled_from_files=yes")
    return GateResult("G0-17", "프롬프트 컴포넌트", True, "", checks)


def gate_proposal_probe() -> GateResult:
    """G0-18: 승인 큐에 들어가는 제안은 대비 또는 명시적 사유를 갖는다.

    사유 없는 미실행은 금지한다 — 제안이 승인 큐에 있는데 왜 비교하지
    않았는지 알 수 없으면, 판단자는 빈칸을 정상으로 읽는다.
    """
    from netwatcher.storage import schemas as schema_module

    checks: list[str] = []
    schema_sql = " ".join(schema_module.ALL_SCHEMAS)
    problems: list[str] = []

    if "config_proposals_probe_check" not in schema_sql:
        problems.append("config_proposals 에 probe 상태 제약을 두고 있지 않다")
    if "probe ? 'status'" not in schema_sql:
        problems.append("probe 가 상태를 요구하지 않는다")
    default = schema_module.CONFIG_PROPOSALS_PROBE_DEFAULT
    if default.get("status") != "skipped" or not default.get("reasons"):
        problems.append("probe 기본값에 사유가 없다")
    checks.append(f"default_status={default.get('status')}")
    checks.append(f"default_reasons={len(default.get('reasons') or [])}")

    # 제안 삽입 경로가 어디서든 대비를 명시하거나 기본값에 맡겨야 한다.
    inserts: list[tuple[str, str]] = []
    for path in sorted((REPO_ROOT / "netwatcher").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"INSERT INTO config_proposals(.*?)RETURNING", text, re.DOTALL):
            inserts.append((str(path.relative_to(REPO_ROOT)), match.group(1)))
    checks.append(f"insert_paths={len(inserts)}")
    for relative, statement in inserts:
        if "probe" not in statement:
            problems.append(f"{relative}: 제안 삽입이 probe 를 명시하지 않는다")

    service = (REPO_ROOT / "netwatcher" / "detection" / "proposals.py").read_text(encoding="utf-8")
    if "run_probe" not in service or "probe=probe" not in service:
        problems.append("제안 서비스가 대비를 계산해 붙이지 않는다")
    checks.append("service_probe=yes")

    if problems:
        return GateResult(
            "G0-18", "제안 대비 계약", False,
            "제안 대비 계약 위반:\n  " + "\n  ".join(problems), checks,
        )
    return GateResult("G0-18", "제안 대비 계약", True, "", checks)


def gate_experience_library() -> GateResult:
    """G0-19: 경험 항목은 근거가 있어야 산다.
    근거 없는 교훈은 다음 제안의 판정을 망친다. 그래서 증거가 비어 있으면
    존재할 수 없고, 근거가 된 제안·판정이 실제로 존재해야 하며, 실행
    대비가 뒷받침할 때만 채택된다.
    """
    from netwatcher.storage import schemas as schema_module

    checks: list[str] = []
    problems: list[str] = []
    schema_sql = " ".join(schema_module.ALL_SCHEMAS)

    if "analysis_experiences_evidence_check" not in schema_sql:
        problems.append("analysis_experiences 에 증거 제약을 두고 있지 않다")
    if "evidence <> '{}'::jsonb" not in schema_sql:
        problems.append("경험 항목의 증거가 비어 있어도 된다")
    if "REFERENCES config_proposals(id)" not in schema_sql:
        problems.append("경험 항목이 근거 제안을 참조하지 않는다")
    if "REFERENCES business_reviews(event_id)" not in schema_sql:
        problems.append("경험 항목이 근거 판정을 참조하지 않는다")
    checks.append("evidence_check=yes")
    checks.append("references=yes")

    experience = (REPO_ROOT / "netwatcher" / "detection" / "experience.py").read_text(encoding="utf-8")
    if "no_comparison" not in experience or "check_adoption(" not in experience:
        problems.append("경험 채택이 실행 대비를 확인하지 않는다")
    if "build_candidate" not in experience:
        problems.append("경험 후보를 만드는 경로가 없다")
    checks.append("adoption_rule=yes")

    repository = (REPO_ROOT / "netwatcher" / "storage" / "repositories.py").read_text(encoding="utf-8")
    if "INSERT INTO analysis_experiences" not in repository or "evidence" not in repository:
        problems.append("경험 항목을 저장하는 경로가 근거를 남기지 않는다")
    checks.append("storage_path=yes")

    server = (REPO_ROOT / "netwatcher" / "web" / "server.py").read_text(encoding="utf-8")
    if "create_experiences_router" not in server:
        problems.append("경험 라이브러리 API 가 등록되지 않았다")
    checks.append("api_mounted=yes")

    if problems:
        return GateResult(
            "G0-19", "경험 라이브러리 계약", False,
            "경험 라이브러리 계약 위반:\n  " + "\n  ".join(problems), checks,
        )
    return GateResult("G0-19", "경험 라이브러리 계약", True, "", checks)


def gate_gate_experience_library() -> GateResult:
    """G0-20: 관문은 자신이 잡은 결함을 기억해야 한다.

    `docs/gates/EXPERIENCE.md` 에 결함 유형 → 관문 → 근거 가 남아 있어야
    한다. 관문을 새로 만들고 그 파일을 고치지 않으면 게이트가 실패한다.
    관문 이름을 잘못 적어도 실패한다. 덮이지 않은 결함은 사유와 함께
    `uncovered` 에 남는다 — 숨기지 않는다.
    """
    path = REPO_ROOT / "docs" / "gates" / "EXPERIENCE.md"
    checks: list[str] = []
    if not path.exists():
        return GateResult("G0-20", "게이트 경험 라이브러리", False, f"파일 없음: {path}", checks)

    text = path.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\s*(.*?)```", text, re.DOTALL)
    if not blocks:
        return GateResult(
            "G0-20", "게이트 경험 라이브러리", False,
            "기계 판독 가능한 json 블록이 없다", checks,
        )
    try:
        data = json.loads(blocks[-1])
    except json.JSONDecodeError as exc:
        return GateResult(
            "G0-20", "게이트 경험 라이브러리", False,
            f"json 블록을 읽을 수 없다: {exc}", checks,
        )

    gates = data.get("gates") or {}
    uncovered = data.get("uncovered") or []
    problems: list[str] = []

    for gate_id, entry in sorted(gates.items()):
        if gate_id not in GATE_BY_ID:
            problems.append(f"{gate_id} 는 존재하지 않는 관문이다")
        if not entry.get("defects"):
            problems.append(f"{gate_id} 에 기록된 결함 유형이 없다")
        if not entry.get("evidence"):
            problems.append(f"{gate_id} 에 근거가 없다")
    checks.append(f"recorded={len(gates)}")

    for gate_id in sorted(GATE_BY_ID):
        if gate_id not in gates:
            problems.append(f"{gate_id} 는 결함 유형이 기록되지 않았다")

    for entry in uncovered:
        if not entry.get("defect") or not entry.get("reason"):
            problems.append("덮이지 않은 결함은 유형과 사유를 함께 적어야 한다")
    checks.append(f"uncovered={len(uncovered)}")

    if problems:
        return GateResult(
            "G0-20", "게이트 경험 라이브러리", False,
            "게이트 경험 라이브러리 위반:\n  " + "\n  ".join(problems), checks,
        )
    return GateResult("G0-20", "게이트 경험 라이브러리", True, "", checks)


def gate_layer_direction() -> GateResult:
    """G0-21: 웹 계층 의존은 조립 지점으로만 들어간다.

    도메인 모듈이 `netwatcher.web` 를 가져오면 웹 계층이 아래로 새어
    들어온다 — 센서 프로세스가 FastAPI 를 끌어들이게 된다. 조립 지점
    (앱을 组는 곳)만 예외다.
    """
    import ast

    composition_roots = {"app.py", "native_console.py", "runtime.py"}
    checks: list[str] = []
    offenders: list[str] = []

    for path in sorted((REPO_ROOT / "netwatcher").rglob("*.py")):
        relative = path.relative_to(REPO_ROOT)
        if relative.parts[1:2] == ("web",):
            continue
        if relative.name in composition_roots:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
            elif isinstance(node, ast.Import):
                module = node.names[0].name if node.names else None
            if module and module.startswith("netwatcher.web"):
                offenders.append(f"{relative}:{node.lineno}")

    checks.append(f"offenders={len(offenders)}")
    checks.append("roots=app.py,native_console.py,ingest/runtime.py")
    if offenders:
        return GateResult(
            "G0-21", "계층 방향", False,
            "웹 계층을 끌어들이는 모듈:\n  " + "\n  ".join(offenders), checks,
        )
    return GateResult("G0-21", "계층 방향", True, "", checks)


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
    gate_mutation_permissions,
    gate_static_analysis,
    gate_event_partitions,
    gate_prompt_components,
    gate_proposal_probe,
    gate_experience_library,
    gate_gate_experience_library,
    gate_layer_direction,
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
    "G0-14": gate_mutation_permissions,
    "G0-15": gate_static_analysis,
    "G0-16": gate_event_partitions,
    "G0-17": gate_prompt_components,
    "G0-18": gate_proposal_probe,
    "G0-19": gate_experience_library,
    "G0-20": gate_gate_experience_library,
    "G0-21": gate_layer_direction,
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
