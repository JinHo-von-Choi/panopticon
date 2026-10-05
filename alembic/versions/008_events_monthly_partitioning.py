"""events 테이블을 월별 range 파티셔닝으로 전환.

Revision ID: 008_events_monthly_partitioning
Revises: 007_devices_host_labels
Create Date: 2026-03-29

안전한 전환 절차:
1. events → events_old 리네임
2. events를 PARTITION BY RANGE (timestamp) 로 재생성
3. 현재 월 파티션 + 전/후 1개월 파티션 생성
4. events_old 데이터를 events로 복사
5. events_old 삭제
6. 인덱스 재생성

수정 이력 (2026-10-05)
----------------------
이 마이그레이션은 깨끗한 DB 에서 `alembic upgrade head` 를 수행할 수 없었다.
두 가지 결함이 있었다.

1. **SQL 실행 방식** — ``conn.execute("SELECT ...")`` 로 원시 문자열을 넘기고 있었다.
   SQLAlchemy 2.x 에서는 실행 가능한 문이 아니어서
   ``ObjectNotExecutableError`` 로 실패했다. 결과 조회는 ``text()`` 로 감싸고,
   DDL/DML 은 ``op.execute()`` 로 실행한다.
2. **컬럼 순서 불일치** — 재생성한 events 의 컬럼 순서가 events_old 와 달랐다.
   ``INSERT INTO events SELECT * FROM events_old`` 는 *위치*로 대응시키므로
   title_key ← reasoning, metadata ← title_key 처럼 값이 엉뚱하게 들어갔다.
   대응 관계를 명시하지 않으면 조용히 데이터가 뒤섞인다. 컬럼 목록을 직접 지정한다.
"""

from __future__ import annotations

from datetime import datetime, timezone

from alembic import op
from sqlalchemy import text

revision = "008_events_monthly_partitioning"
down_revision = "007_devices_host_labels"
branch_labels = None
depends_on = None

# events_old 와 동일한 순서로 명시한다. 순서가 바뀌면 데이터가 뒤섞인다.
EVENTS_COLUMNS: tuple[str, ...] = (
    "id",
    "timestamp",
    "engine",
    "severity",
    "title",
    "description",
    "source_ip",
    "source_mac",
    "dest_ip",
    "dest_mac",
    "metadata",
    "packet_info",
    "resolved",
    "reasoning",
    "title_key",
    "description_key",
    "mitre_attack_id",
    "threat_level",
)

_IS_PARTITIONED_SQL = text("""
    SELECT EXISTS (
        SELECT 1 FROM pg_partitioned_table pt
        JOIN pg_class c ON c.oid = pt.partrelid
        WHERE c.relname = 'events'
    )
""")


def _add_months(dt: datetime, months: int) -> datetime:
    """datetime에 월을 더한다."""
    month = dt.month - 1 + months
    year  = dt.year + month // 12
    month = month % 12 + 1
    return dt.replace(year=year, month=month, day=1)


def _month_start(year: int, month: int) -> str:
    return f"{year:04d}-{month:02d}-01"


def _partition_name(year: int, month: int) -> str:
    return f"events_{year:04d}_{month:02d}"


def _is_partitioned() -> bool:
    """events 가 이미 파티셔닝되어 있는지 확인한다."""
    return bool(op.get_bind().execute(_IS_PARTITIONED_SQL).scalar())


def _create_events_partitioned() -> None:
    """PARTITION BY RANGE (timestamp) 로 events 를 생성한다."""
    op.execute("""
        CREATE TABLE events (
            id          BIGSERIAL       NOT NULL,
            timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            engine      VARCHAR(64)     NOT NULL,
            severity    VARCHAR(16)     NOT NULL,
            title       VARCHAR(512)    NOT NULL,
            description TEXT            NOT NULL DEFAULT '',
            source_ip   INET,
            source_mac  MACADDR,
            dest_ip     INET,
            dest_mac    MACADDR,
            metadata    JSONB           NOT NULL DEFAULT '{}',
            packet_info JSONB           NOT NULL DEFAULT '{}',
            resolved    BOOLEAN         NOT NULL DEFAULT FALSE,
            reasoning   TEXT,
            title_key        TEXT,
            description_key  TEXT,
            mitre_attack_id  VARCHAR(64),
            threat_level     SMALLINT NOT NULL DEFAULT 0,
            PRIMARY KEY (id, timestamp)
        ) PARTITION BY RANGE (timestamp)
    """)


def _create_partitions(from_dt: datetime) -> None:
    """from_dt 의 달부터 현재 달 +3개월 까지 파티션을 만든다."""
    start = datetime(from_dt.year, from_dt.month, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    end = _add_months(datetime(now.year, now.month, 1, tzinfo=timezone.utc), 3)

    current = start
    while current < end:
        name = _partition_name(current.year, current.month)
        nxt  = _add_months(current, 1)
        op.execute(
            f"CREATE TABLE {name} PARTITION OF events "
            f"FOR VALUES FROM ('{_month_start(current.year, current.month)}') "
            f"TO ('{_month_start(nxt.year, nxt.month)}')"
        )
        current = nxt


def _recreate_indexes() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_source_ip "
        "ON events(source_ip) WHERE source_ip IS NOT NULL"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_mitre "
        "ON events(mitre_attack_id) WHERE mitre_attack_id IS NOT NULL"
    )


def upgrade() -> None:
    conn = op.get_bind()

    if _is_partitioned():
        return

    # 1. 기존 events 테이블 리네임
    op.execute("ALTER TABLE events RENAME TO events_old")

    # 시퀀스 이름 확인 (events_id_seq가 존재하면 유지)
    seq_exists = conn.execute(
        text("SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'events_id_seq')")
    ).scalar()

    # 2. 파티셔닝된 events 테이블 생성
    _create_events_partitioned()

    if seq_exists:
        op.execute("ALTER SEQUENCE events_id_seq OWNED BY events.id")
        op.execute("ALTER TABLE events ALTER COLUMN id SET DEFAULT nextval('events_id_seq')")

    # 3. 파티션 생성: 데이터가 있을 수 있는 범위 + 미래 3개월
    row = conn.execute(
        text("SELECT MIN(timestamp), MAX(timestamp) FROM events_old")
    ).fetchone()

    now = datetime.now(timezone.utc)
    min_ts = row[0]
    if min_ts is not None:
        if isinstance(min_ts, str):
            min_ts = datetime.fromisoformat(min_ts)
        start = datetime(min_ts.year, min_ts.month, 1, tzinfo=timezone.utc)
    else:
        start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    _create_partitions(start)

    # 4. 데이터 복사 — 대응 관계를 명시한다 (SELECT * 는 금지)
    columns = ", ".join(EVENTS_COLUMNS)
    op.execute(f"INSERT INTO events ({columns}) SELECT {columns} FROM events_old")

    # 5. events_old 삭제
    op.execute("DROP TABLE events_old")

    # 6. 인덱스 재생성 (파티셔닝된 테이블에서는 각 파티션에 자동 전파)
    _recreate_indexes()


def downgrade() -> None:
    """파티셔닝된 events 테이블을 일반 테이블로 되돌린다."""
    if not _is_partitioned():
        return

    # 1. 임시 테이블에 데이터 백업
    op.execute("CREATE TABLE events_backup AS SELECT * FROM events")

    # 2. 파티셔닝된 테이블 삭제
    op.execute("DROP TABLE events CASCADE")

    # 3. 일반 테이블로 재생성
    op.execute("""
        CREATE TABLE events (
            id          BIGSERIAL       PRIMARY KEY,
            timestamp   TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            engine      VARCHAR(64)     NOT NULL,
            severity    VARCHAR(16)     NOT NULL,
            title       VARCHAR(512)    NOT NULL,
            description TEXT            NOT NULL DEFAULT '',
            source_ip   INET,
            source_mac  MACADDR,
            dest_ip     INET,
            dest_mac    MACADDR,
            metadata    JSONB           NOT NULL DEFAULT '{}',
            packet_info JSONB           NOT NULL DEFAULT '{}',
            resolved    BOOLEAN         NOT NULL DEFAULT FALSE,
            reasoning   TEXT,
            title_key        TEXT,
            description_key  TEXT,
            mitre_attack_id  VARCHAR(64),
            threat_level     SMALLINT NOT NULL DEFAULT 0
        )
    """)

    # 4. 데이터 복구 — 파티셔닝 전과 동일한 순서로 명시한다
    columns = ", ".join(EVENTS_COLUMNS)
    op.execute(f"INSERT INTO events ({columns}) SELECT {columns} FROM events_backup")
    op.execute("DROP TABLE events_backup")

    # 5. 인덱스 재생성
    _recreate_indexes()
