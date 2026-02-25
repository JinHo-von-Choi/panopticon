"""baseline: 현재 스키마 전체 (5 테이블 + 13 인덱스)

Revision ID: 001_baseline
Revises: None
Create Date: 2026-02-23

기존 배포: alembic stamp head 로 현재 상태를 마킹
신규 배포: alembic upgrade head 로 전체 생성
"""
from typing import Sequence, Union

from alembic import op

revision: str = "001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- events ---
    op.execute("""
        CREATE TABLE IF NOT EXISTS events (
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
            resolved    BOOLEAN         NOT NULL DEFAULT FALSE
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip) WHERE source_ip IS NOT NULL")

    # --- devices ---
    op.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id            BIGSERIAL       PRIMARY KEY,
            mac_address   MACADDR         UNIQUE NOT NULL,
            ip_address    INET,
            hostname      VARCHAR(255),
            vendor        VARCHAR(255),
            nickname      VARCHAR(128),
            notes         TEXT            NOT NULL DEFAULT '',
            first_seen    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            last_seen     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            is_known      BOOLEAN         NOT NULL DEFAULT FALSE,
            total_packets BIGINT          NOT NULL DEFAULT 0,
            total_bytes   BIGINT          NOT NULL DEFAULT 0,
            open_ports    JSONB           NOT NULL DEFAULT '[]',
            os_hint       VARCHAR(128)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address) WHERE ip_address IS NOT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC)")

    # --- custom_blocklist ---
    op.execute("""
        CREATE TABLE IF NOT EXISTS custom_blocklist (
            id          BIGSERIAL       PRIMARY KEY,
            entry_type  VARCHAR(16)     NOT NULL CHECK (entry_type IN ('ip', 'domain')),
            value       VARCHAR(512)    NOT NULL,
            source      VARCHAR(128)    NOT NULL DEFAULT 'Custom',
            notes       TEXT            NOT NULL DEFAULT '',
            created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

            CONSTRAINT uq_blocklist_type_value UNIQUE (entry_type, value)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_type ON custom_blocklist(entry_type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_value ON custom_blocklist(value)")

    # --- traffic_stats ---
    op.execute("""
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id            BIGSERIAL       PRIMARY KEY,
            timestamp     TIMESTAMPTZ     NOT NULL,
            total_packets BIGINT          NOT NULL DEFAULT 0,
            total_bytes   BIGINT          NOT NULL DEFAULT 0,
            tcp_count     BIGINT          NOT NULL DEFAULT 0,
            udp_count     BIGINT          NOT NULL DEFAULT 0,
            arp_count     BIGINT          NOT NULL DEFAULT 0,
            dns_count     BIGINT          NOT NULL DEFAULT 0
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_traffic_stats_ts ON traffic_stats(timestamp DESC)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_stats_ts_unique ON traffic_stats(timestamp)")

    # --- incidents ---
    op.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id                BIGSERIAL       PRIMARY KEY,
            severity          VARCHAR(16)     NOT NULL,
            title             VARCHAR(512)    NOT NULL,
            description       TEXT            NOT NULL DEFAULT '',
            alert_ids         BIGINT[]        NOT NULL DEFAULT '{}',
            source_ips        TEXT[]          NOT NULL DEFAULT '{}',
            engines           TEXT[]          NOT NULL DEFAULT '{}',
            kill_chain_stages TEXT[]          NOT NULL DEFAULT '{}',
            rule              VARCHAR(64)     NOT NULL DEFAULT '',
            created_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            updated_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            resolved          BOOLEAN         NOT NULL DEFAULT FALSE
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved) WHERE resolved = FALSE")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS incidents")
    op.execute("DROP TABLE IF EXISTS traffic_stats")
    op.execute("DROP TABLE IF EXISTS custom_blocklist")
    op.execute("DROP TABLE IF EXISTS devices")
    op.execute("DROP TABLE IF EXISTS events")
