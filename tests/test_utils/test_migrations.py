"""마이그레이션 정적 검사 (PR 04, 게이트 G4 보조).

`alembic upgrade head` 가 깨끗한 DB 에서 실패한 실측 결함에 대한 회귀 가드다.

1. **원시 문자열 SQL** — SQLAlchemy 2.x 에서 ``conn.execute("SELECT ...")`` 는
   ``ObjectNotExecutableError`` 로 실패한다. 조회는 ``text()`` 로 감싸야 한다.
2. **``INSERT ... SELECT *``** — 컬럼 순서가 어긋나면 조용히 데이터가 뒤섞인다.
   파티셔닝 전환처럼 스키마를 재생성하는 마이그레이션은 대응 관계를 명시해야 한다.
3. **revision 사슬** — down_revision 이 실제 존재하는 revision 을 가리켜야 한다.

DB 를 필요로 하지 않는 정적 검사만 담는다. 실제 적용 여부는 ``scripts/gates.py``
의 G0-4 게이트가 담당한다.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

VERSIONS_DIR = Path(__file__).resolve().parents[2] / "alembic" / "versions"

_PARTITIONING_MIGRATION = "008_events_monthly_partitioning.py"


def _migration_files() -> list[Path]:
    if not VERSIONS_DIR.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("alembic/versions not found")
    return sorted(VERSIONS_DIR.glob("*.py"))


def _trees() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text(encoding="utf-8"))) for p in _migration_files()]


def test_migrations_exist():
    assert _migration_files(), "마이그레이션 파일이 하나도 없다"


@pytest.mark.parametrize(
    "path,tree",
    _trees(),
    ids=lambda v: v.name if isinstance(v, Path) else "",
)
def test_no_raw_string_conn_execute(path: Path, tree: ast.Module):
    """conn.execute()/bind.execute() 는 text() 로 감싼 SQLAlchemy 문을 요구한다."""
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "execute":
            continue
        owner = func.value
        owner_name = getattr(owner, "attr", getattr(owner, "id", ""))
        if owner_name not in {"conn", "connection", "bind", "get_bind"}:
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, (
        "원시 문자열을 conn.execute() 에 넘겼다 (text() 필요):\n" + "\n".join(offenders)
    )


@pytest.mark.parametrize("path,tree", _trees(), ids=lambda v: v.name if isinstance(v, Path) else "")
def test_no_insert_select_star_in_schema_migration(path: Path, tree: ast.Module):
    """스키마를 재생성하는 마이그레이션은 SELECT * 로 복사하면 안 된다."""
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in {"execute", "sql"}:
            continue
        first = node.args[0] if node.args else None
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            continue
        sql = " ".join(first.value.upper().split())
        if sql.startswith("INSERT") and "SELECT *" in sql:
            offenders.append(f"{path.name}:{node.lineno}")

    assert not offenders, (
        "INSERT ... SELECT * 는 컬럼 순서에 의존한다 (명시해야 한다):\n" + "\n".join(offenders)
    )


def test_revision_chain_is_linear_and_complete():
    """각 revision 의 down_revision 이 실제 revision 을 가리켜야 한다."""
    revisions: dict[str, str | None] = {}
    for path in _migration_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found: dict[str, str | None] = {}
        for node in tree.body:
            # `revision = "..."` 와 `revision: str = "..."` 두 형태 모두 지원
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            else:
                continue
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if target.id in {"revision", "down_revision"}:
                    found[target.id] = (
                        value.value
                        if isinstance(value, ast.Constant) and isinstance(value.value, str)
                        else None
                    )
        if "revision" in found:
            revisions[found["revision"]] = found.get("down_revision")

    assert revisions, "revision 을 선언한 마이그레이션이 없다"
    for rev, down in revisions.items():
        if down is None:
            continue
        assert down in revisions, f"{rev} 의 down_revision({down}) 이 존재하지 않는다"

    # head 는 정확히 하나여야 한다 (분기/끊김이 없어야 한다)
    parents = {d for d in revisions.values() if d is not None}
    heads = set(revisions) - parents
    assert len(heads) == 1, f"revision head 가 하나가 아니다: {sorted(heads)}"


def test_partitioning_migration_declares_explicit_columns():
    """파티셔닝 마이그레이션은 컬럼 목록을 명시해야 한다."""
    path = VERSIONS_DIR / _PARTITIONING_MIGRATION
    if not path.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip(f"{_PARTITIONING_MIGRATION} not found")

    text_src = path.read_text(encoding="utf-8")
    assert "EVENTS_COLUMNS" in text_src

    tree = ast.parse(text_src)
    declared = None
    for node in ast.walk(tree):
        # `EVENTS_COLUMNS: tuple[str, ...] = (...)` annotated 할당 형태
        targets = (
            node.targets if isinstance(node, ast.Assign)
            else [node.target] if isinstance(node, ast.AnnAssign)
            else []
        )
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "EVENTS_COLUMNS":
                declared = [e.value for e in node.value.elts]
    assert declared, "EVENTS_COLUMNS 선언을 찾지 못했다"
    # 파티셔닝 키는 반드시 포함되어야 한다
    assert "timestamp" in declared
    assert "id" in declared


def test_partitioned_primary_key_includes_partition_key():
    """PostgreSQL 파티션 테이블의 PK 는 파티션 키를 포함해야 한다."""
    path = VERSIONS_DIR / _PARTITIONING_MIGRATION
    if not path.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip(f"{_PARTITIONING_MIGRATION} not found")

    text_src = path.read_text(encoding="utf-8")
    assert "PRIMARY KEY (id, timestamp)" in text_src
    assert "PARTITION BY RANGE (timestamp)" in text_src


# ------------------------------------------------------------------
# 마이그레이션 ↔ 스키마 정의 일치 (PR 10 노예 검증에서 발견)
# ------------------------------------------------------------------

def test_config_proposals_defined_in_both_migration_and_schemas():
    """config_proposals 는 두 곳 모두에 정의돼 있어야 한다.

    ``Database.connect()`` 는 ``ALL_SCHEMAS`` 를 실행하고, 배포는
    ``alembic upgrade`` 를 쓴다. 한쪽에만 있으면 한 경로에서 테이블이 없다.
    마이그레이션만 있고 스키마 목록에 없으면, 테스트 스키마에서 저장소가
    테이블을 찾지 못해 검증 자체가 불가능해진다.
    """
    from netwatcher.storage.schemas import ALL_SCHEMAS

    joined = "\n".join(ALL_SCHEMAS)
    assert "config_proposals" in joined, "ALL_SCHEMAS 에 config_proposals 가 없다"

    mig = VERSIONS_DIR / "010_config_proposals.py"
    if not mig.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("010_config_proposals.py not found")
    text = mig.read_text(encoding="utf-8")
    assert "config_proposals" in text


def test_config_proposals_columns_match_migration():
    """두 정의의 컬럼이 어긋나면 한쪽에서만 INSERT 가 된다."""
    from netwatcher.storage.schemas import ALL_SCHEMAS

    schema_sql = "\n".join(s for s in ALL_SCHEMAS if "config_proposals" in s)
    mig_sql = (VERSIONS_DIR / "010_config_proposals.py").read_text(encoding="utf-8")

    columns = [
        "id", "engine", "params", "reason", "source", "status", "before",
        "created_at", "decided_at", "decided_by", "decision_note",
        "applied", "apply_error",
    ]
    for col in columns:
        assert col in schema_sql, f"스키마 정의에 {col} 가 없다"
        assert col in mig_sql, f"마이그레이션에 {col} 가 없다"
