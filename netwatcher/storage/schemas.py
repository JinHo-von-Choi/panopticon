"""NetWatcher용 PostgreSQL 스키마 정의."""

EVENTS_TABLE = """
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
);
"""

EVENTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine);",
    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip) WHERE source_ip IS NOT NULL;",
]

DEVICES_TABLE = """
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
);
"""

DEVICES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);",
    "CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address) WHERE ip_address IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);",
]

CUSTOM_BLOCKLIST_TABLE = """
CREATE TABLE IF NOT EXISTS custom_blocklist (
    id          BIGSERIAL       PRIMARY KEY,
    entry_type  VARCHAR(16)     NOT NULL CHECK (entry_type IN ('ip', 'domain')),
    value       VARCHAR(512)    NOT NULL,
    source      VARCHAR(128)    NOT NULL DEFAULT 'Custom',
    notes       TEXT            NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_blocklist_type_value UNIQUE (entry_type, value)
);
"""

CUSTOM_BLOCKLIST_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_blocklist_type ON custom_blocklist(entry_type);",
    "CREATE INDEX IF NOT EXISTS idx_blocklist_value ON custom_blocklist(value);",
]

TRAFFIC_STATS_TABLE = """
CREATE TABLE IF NOT EXISTS traffic_stats (
    id            BIGSERIAL       PRIMARY KEY,
    timestamp     TIMESTAMPTZ     NOT NULL,
    total_packets BIGINT          NOT NULL DEFAULT 0,
    total_bytes   BIGINT          NOT NULL DEFAULT 0,
    tcp_count     BIGINT          NOT NULL DEFAULT 0,
    udp_count     BIGINT          NOT NULL DEFAULT 0,
    arp_count     BIGINT          NOT NULL DEFAULT 0,
    dns_count     BIGINT          NOT NULL DEFAULT 0
);
"""

TRAFFIC_STATS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_traffic_stats_ts ON traffic_stats(timestamp DESC);",
    # 타임스탬프 중복 행 방지를 위한 유니크 제약조건
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_stats_ts_unique ON traffic_stats(timestamp);",
]

INCIDENTS_TABLE = """
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
);
"""

INCIDENTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_resolved ON incidents(resolved) WHERE resolved = FALSE;",
]

ALL_SCHEMAS = [
    EVENTS_TABLE,
    *EVENTS_INDEXES,
    DEVICES_TABLE,
    *DEVICES_INDEXES,
    CUSTOM_BLOCKLIST_TABLE,
    *CUSTOM_BLOCKLIST_INDEXES,
    TRAFFIC_STATS_TABLE,
    *TRAFFIC_STATS_INDEXES,
    INCIDENTS_TABLE,
    *INCIDENTS_INDEXES,
]
