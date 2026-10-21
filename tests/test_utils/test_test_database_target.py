"""테스트 하네스가 지정한 DB 대상이 환경변수로 바뀌지 않는지 검증한다.

Config.load()는 NETWATCHER_DB_* 환경변수를 YAML 뒤에 덮어쓴다. 개발자의 .env
에 운영 DB가 적혀 있으면 시험 스키마가 그 DB에 만들어지고 지워진다. 시험
하네스는 로드 직후 postgresql 구간을 다시 고정해 이 경로를 막는다.

여기에는 DB 부재 시 "건너뛰기" 계약이 **모든 DB 시험에** 적용되는지도
검증한다. 2026-10-22 실측: psycopg2 로 직접 접속하는 8개 시험이
``NETWATCHER_TEST_ALLOW_DB_SKIP=1`` 일 때도 "실패" 로 끝났다. 픽스처 이름
목록만으로 DB 필요 여부를 판정했기 때문이다.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import asyncpg
import pytest

from netwatcher.utils.config import Config


def _write_config(tmp_path, host: str, port: int, database: str) -> str:
    path = tmp_path / "target.yaml"
    path.write_text(
        f"netwatcher:\n"
        f"  postgresql:\n"
        f"    host: \"{host}\"\n"
        f"    port: {port}\n"
        f"    database: \"{database}\"\n"
        f"    username: \"user\"\n"
        f"    password: \"pass\"\n",
        encoding="utf-8",
    )
    return str(path)


def test_env_override_wins_over_yaml(tmp_path, monkeypatch):
    """환경변수가 YAML 을 덮어쓰는 동작 자체를 고정한다."""
    monkeypatch.setenv("NETWATCHER_DB_HOST", "env-host")
    monkeypatch.setenv("NETWATCHER_DB_NAME", "env-db")
    config = Config.load(_write_config(tmp_path, "yaml-host", 5432, "yaml-db"))

    assert config.get("postgresql.host") == "env-host"
    assert config.get("postgresql.database") == "env-db"


def test_config_fixture_pins_test_database(config):
    """시험 픽스처는 환경변수가 가리키는 DB가 아니라 지정된 시험 DB를 쓴다."""
    section = config.section("postgresql")

    assert section["host"] == os.environ.get("NETWATCHER_TEST_DB_HOST", "localhost")
    assert section["database"] == os.environ.get("NETWATCHER_TEST_DB_NAME", "netwatcher_test")
    assert section["username"] == os.environ.get("NETWATCHER_TEST_DB_USER", "netwatcher")
    assert section["port"] == int(os.environ.get("NETWATCHER_TEST_DB_PORT", "5432"))


def test_config_fixture_ignores_runtime_db_env(config, monkeypatch):
    """NETWATCHER_DB_* 로 시험 DB 대상이 바뀌지 않는다."""
    from tests.conftest import _TEST_DB

    monkeypatch.setenv("NETWATCHER_DB_HOST", "some-other-host")
    monkeypatch.setenv("NETWATCHER_DB_NAME", "some-other-db")

    # Config.load() 는 환경변수를 반영한다 — 그래서 시험 하네스가 다시 고정한다.
    reloaded = Config.load(config.config_path)
    assert reloaded.get("postgresql.host") == "some-other-host"

    # 시험 하네스가 쓰는 값은 .env 가 아니라 지정된 시험 DB 다.
    assert _TEST_DB["host"] == os.environ.get("NETWATCHER_TEST_DB_HOST", "localhost")
    assert _TEST_DB["database"] == os.environ.get(
        "NETWATCHER_TEST_DB_NAME", "netwatcher_test"
    )


def test_db_skip_is_opt_in(monkeypatch):
    """DB 부재 시 건너뛰기는 기본이 아니다 — 명시적으로 허용해야 한다."""
    from tests.conftest import _allow_db_skip

    monkeypatch.delenv("NETWATCHER_TEST_ALLOW_DB_SKIP", raising=False)
    assert _allow_db_skip() is False

    monkeypatch.setenv("NETWATCHER_TEST_ALLOW_DB_SKIP", "1")
    assert _allow_db_skip() is True

    monkeypatch.setenv("NETWATCHER_TEST_ALLOW_DB_SKIP", "false")
    assert _allow_db_skip() is False


@pytest.mark.asyncio
async def test_unreachable_database_fails_without_retry_wait(config):
    """재시도 횟수를 1로 두면 도달 불가 DB 에서 즉시 실패한다."""
    import time

    from netwatcher.storage.database import Database

    broken = Config.load(config.config_path)
    broken.raw["postgresql"] = {
        **broken.raw["postgresql"],
        "host": "127.0.0.1",
        "port": 1,
    }

    database = Database(broken)
    started = time.monotonic()
    with pytest.raises((OSError, asyncpg.PostgresError)):
        await database.connect(max_retries=1)
    assert time.monotonic() - started < 5.0


# ── DB 필요 시험의 계약 ──────────────────────────────────────────────
#
# DB 에 접속하는 시험은 두 가지로 "DB 가 필요하다" 고 선언해야 한다.
# 1. DB 픽스처를 요청한다 (db · event_repo · device_repo …).
# 2. @pytest.mark.requires_db 를 단다 (psycopg2 직접 접속 시험).
#
# 어느 쪽이든 tests/conftest.py 의 스킵 판정이 잡는다. 선언이 빠지면
# DB 부재 환경에서 "건너뛰기" 가 아니라 "실패" 로 끝나고, 문서화된 로컬
# 절차가 깨진다.

_DB_FIXTURE_NAMES = frozenset({
    "db", "event_repo", "device_repo", "stats_repo", "blocklist_repo", "incident_repo",
})

# DB 에 접속하는 호출. 문자열로 검사하므로 가짜 서버를 띄우는 시험
# (test_database_tls) 은 아래 "설정된 서버" 조건과 함께 걸러진다.
_CONNECTION_CALLS = (
    "psycopg2.connect",
    "asyncpg.connect",
    "command.upgrade",
    "command.downgrade",
    "pg_dump",
    "pg_restore",
)

# 시험하네스가 지정한 PostgreSQL 을 가리키는 표현.
_CONFIGURED_SERVER = (
    "section(\"postgresql\")",
    "section('postgresql')",
    "_TEST_DB",
)

_TESTS_ROOT = Path(__file__).resolve().parents[1]


def _module_marks(source: str) -> set[str]:
    """모듈 수준 pytestmark 에 붙은 마커 이름을 돌려준다."""
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - 파싱 실패는 시험이 아니라 파일 문제다
        return set()
    marks: set[str] = set()
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
        if "pytestmark" not in targets or node.value is None:
            continue
        for element in ast.walk(node.value):
            if isinstance(element, ast.Attribute) and element.attr == "requires_db":
                marks.add("requires_db")
    return marks


def _db_touching_tests() -> list[tuple[str, str]]:
    """설정된 PostgreSQL 에 접속하는 시험 목록을 돌려준다."""
    found: list[tuple[str, str]] = []
    for path in sorted(_TESTS_ROOT.rglob("test_*.py")):
        if path.resolve() == Path(__file__).resolve():
            continue
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if not any(call in segment for call in _CONNECTION_CALLS):
                continue
            if not any(target in segment for target in _CONFIGURED_SERVER):
                continue
            found.append((str(path.relative_to(_TESTS_ROOT)), node.name))
    return found


def test_db_touching_tests_are_declared():
    """DB 에 접속하는 시험은 모두 "DB 가 필요하다" 고 선언해야 한다.

    선언이 빠지면 DB 부재 환경에서 건너뛰지 못하고 실패한다. 문서화된
    로컬 절차가 깨지는 것이기 때문에 이 계약을 시험으로 고정한다.
    """
    unguarded: list[str] = []
    for path in sorted(_TESTS_ROOT.rglob("test_*.py")):
        if path.resolve() == Path(__file__).resolve():
            continue
        source = path.read_text(encoding="utf-8")
        module_marks = _module_marks(source)
        try:
            tree = ast.parse(source)
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if not any(call in segment for call in _CONNECTION_CALLS):
                continue
            if not any(target in segment for target in _CONFIGURED_SERVER):
                continue
            arguments = {argument.arg for argument in node.args.args}
            declared = bool(arguments & _DB_FIXTURE_NAMES) or "requires_db" in module_marks
            if not declared:
                for decorator in node.decorator_list:
                    if "requires_db" in (ast.get_source_segment(source, decorator) or ""):
                        declared = True
                        break
            if not declared:
                unguarded.append(f"{path.relative_to(_TESTS_ROOT)}::{node.name}")

    assert not unguarded, (
        "DB 에 접속하지만 DB 필요를 선언하지 않은 시험이 있다 — "
        "@pytest.mark.requires_db 를 달거나 DB 픽스처를 요청하라:\n  "
        + "\n  ".join(unguarded)
    )


def test_db_touching_tests_are_found():
    """검사 대상이 실제로 잡히는지 확인한다 — 검사기가 아무것도 안 잡으면
    위 계약은 항상 통과한다 (빈 목록에 대한 assertions 는 조용히 통과한다).
    """
    found = _db_touching_tests()

    assert found, "DB 접속 시험이 하나도 잡히지 않았다 — 검사 기준이 깨졌다"
    assert any(name == "test_previous_release_upgrade_and_backup_restore" for _, name in found), (
        "psycopg2 직접 접속 시험이 잡히지 않았다"
    )


def test_requires_db_marker_is_registered():
    """마커가 등록되어야 경고 없이 쓸 수 있다."""
    from pathlib import Path as _Path

    pyproject = (_Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8")

    assert "requires_db" in pyproject, "pyproject.toml 에 requires_db 마커 등록이 없다"
