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
"""

from __future__ import annotations

from datetime import datetime, timezone

from alembic import op


revision = "008_events_monthly_partitioning"
down_revision = "007_devices_host_labels"
branch_labels = None
depends_on = None


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


def upgrade() -> None:
    conn = op.get_bind()

    # 이미 파티셔닝되어 있으면 스킵
    is_partitioned = conn.execute(
        """SELECT EXISTS (
            SELECT 1 FROM pg_partitioned_table pt
            JOIN pg_class c ON c.oid = pt.partrelid
            WHERE c.relname = 'events'
        )"""
    ).scalar()
    if is_partitioned:
        return

    # 1. 기존 events 테이블 리네임
    conn.execute("ALTER TABLE events RENAME TO events_old")

    # 시퀀스 이름 확인 (events_id_seq가 존재하면 유지)
    seq_exists = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'events_id_seq')"
    ).scalar()

    # 2. 파티셔닝된 events 테이블 생성
    conn.execute("""
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
            title_key        TEXT,
            description_key  TEXT,
            metadata         JSONB           NOT NULL DEFAULT '{}',
            packet_info      JSONB           NOT NULL DEFAULT '{}',
            resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
            reasoning        TEXT,
            mitre_attack_id  VARCHAR(64),
            threat_level     SMALLINT        NOT NULL DEFAULT 0,
            PRIMARY KEY (id, timestamp)
        ) PARTITION BY RANGE (timestamp)
    """)

    # 시퀀스를 새 테이블에 연결
    if seq_exists:
        conn.execute(
            "ALTER SEQUENCE events_id_seq OWNED BY events.id"
        )
        conn.execute(
            "ALTER TABLE events ALTER COLUMN id SET DEFAULT nextval('events_id_seq')"
        )

    # 3. 파티션 생성: 데이터가 있을 수 있는 범위 + 미래 2개월
    #    events_old에서 최소/최대 timestamp를 조회하여 필요한 파티션을 모두 생성
    row = conn.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM events_old"
    ).fetchone()

    now = datetime.now(timezone.utc)
    min_ts = row[0]
    max_ts = row[1]

    # 파티션이 필요한 월 범위 계산
    if min_ts is not None:
        # 문자열이면 파싱
        if isinstance(min_ts, str):
            min_ts = datetime.fromisoformat(min_ts)
        if isinstance(max_ts, str):
            max_ts = datetime.fromisoformat(max_ts)
        start = datetime(min_ts.year, min_ts.month, 1, tzinfo=timezone.utc)
    else:
        start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)

    end = _add_months(datetime(now.year, now.month, 1, tzinfo=timezone.utc), 3)

    current = start
    while current < end:
        name = _partition_name(current.year, current.month)
        nxt  = _add_months(current, 1)
        conn.execute(
            f"CREATE TABLE {name} PARTITION OF events "
            f"FOR VALUES FROM ('{_month_start(current.year, current.month)}') "
            f"TO ('{_month_start(nxt.year, nxt.month)}')"
        )
        current = nxt

    # 4. 데이터 복사
    conn.execute("INSERT INTO events SELECT * FROM events_old")

    # 5. events_old 삭제
    conn.execute("DROP TABLE events_old")

    # 6. 인덱스 재생성 (파티셔닝된 테이블에서는 각 파티션에 자동 전파)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_source_ip "
        "ON events(source_ip) WHERE source_ip IS NOT NULL"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_mitre "
        "ON events(mitre_attack_id) WHERE mitre_attack_id IS NOT NULL"
    )


def downgrade() -> None:
    """파티셔닝된 events 테이블을 일반 테이블로 되돌린다."""
    conn = op.get_bind()

    is_partitioned = conn.execute(
        """SELECT EXISTS (
            SELECT 1 FROM pg_partitioned_table pt
            JOIN pg_class c ON c.oid = pt.partrelid
            WHERE c.relname = 'events'
        )"""
    ).scalar()
    if not is_partitioned:
        return

    # 1. 임시 테이블에 데이터 백업
    conn.execute("""
        CREATE TABLE events_backup AS SELECT * FROM events
    """)

    # 2. 파티셔닝된 테이블 삭제
    conn.execute("DROP TABLE events CASCADE")

    # 3. 일반 테이블로 재생성
    conn.execute("""
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
            title_key        TEXT,
            description_key  TEXT,
            metadata         JSONB           NOT NULL DEFAULT '{}',
            packet_info      JSONB           NOT NULL DEFAULT '{}',
            resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
            reasoning        TEXT,
            mitre_attack_id  VARCHAR(64),
            threat_level     SMALLINT        NOT NULL DEFAULT 0
        )
    """)

    # 4. 데이터 복구
    conn.execute("INSERT INTO events SELECT * FROM events_backup")
    conn.execute("DROP TABLE events_backup")

    # 5. 인덱스 재생성
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_source_ip "
        "ON events(source_ip) WHERE source_ip IS NOT NULL"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_mitre "
        "ON events(mitre_attack_id) WHERE mitre_attack_id IS NOT NULL"
    )
