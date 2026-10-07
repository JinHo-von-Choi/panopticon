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
    title_key        TEXT,
    description_key  TEXT,
    metadata         JSONB           NOT NULL DEFAULT '{}',
    packet_info      JSONB           NOT NULL DEFAULT '{}',
    resolved         BOOLEAN         NOT NULL DEFAULT FALSE,
    reasoning        TEXT,
    mitre_attack_id  VARCHAR(64),
    threat_level     SMALLINT        NOT NULL DEFAULT 0
);
"""

EVENTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine);",
    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip) WHERE source_ip IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_attack_id) WHERE mitre_attack_id IS NOT NULL;",
]

DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS devices (
    id               BIGSERIAL    PRIMARY KEY,
    mac_address      MACADDR      UNIQUE NOT NULL,
    ip_address       INET,
    hostname         VARCHAR(255),
    vendor           VARCHAR(255),
    nickname         VARCHAR(128),
    notes            TEXT         NOT NULL DEFAULT '',
    first_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    is_known         BOOLEAN      NOT NULL DEFAULT FALSE,
    total_packets    BIGINT       NOT NULL DEFAULT 0,
    total_bytes      BIGINT       NOT NULL DEFAULT 0,
    open_ports       JSONB        NOT NULL DEFAULT '[]',
    os_hint          VARCHAR(128),
    device_type      VARCHAR(32)  NOT NULL DEFAULT 'unknown',
    hostname_sources JSONB        NOT NULL DEFAULT '{}',
    ip_history       JSONB        NOT NULL DEFAULT '[]',
    host_labels      JSONB        NOT NULL DEFAULT '[]'
);
"""

DEVICES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);",
    "CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address) WHERE ip_address IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);",
    "CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type) WHERE device_type != 'unknown';",
    "CREATE INDEX IF NOT EXISTS idx_devices_host_labels ON devices USING gin(host_labels) WHERE host_labels != '[]';",
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

USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL          PRIMARY KEY,
    username        VARCHAR(100)    UNIQUE NOT NULL,
    password_hash   VARCHAR(200)    NOT NULL,
    role            VARCHAR(20)     NOT NULL DEFAULT 'viewer',
    created_at      TIMESTAMPTZ     DEFAULT NOW(),
    last_login      TIMESTAMPTZ
);
"""

AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL          PRIMARY KEY,
    user_id     VARCHAR(100),
    action      VARCHAR(50)     NOT NULL,
    resource    VARCHAR(200),
    details     JSONB,
    ip          VARCHAR(45),
    created_at  TIMESTAMPTZ     DEFAULT NOW()
);
"""

AUDIT_LOG_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);",
]

# 설정 제안 승인 큐 (PR 10). alembic 010 과 동일한 정의를 유지한다.
# Database.connect() 가 이 목록을 실행하므로, 여기에 없으면 저장소가
# 마이그레이션 없이 만든 스키마에서 테이블을 찾지 못한다.
CONFIG_PROPOSALS_TABLE = """
CREATE TABLE IF NOT EXISTS config_proposals (
    id            SERIAL          PRIMARY KEY,
    engine        VARCHAR(64)     NOT NULL,
    params        JSONB           NOT NULL,
    reason        TEXT            NOT NULL DEFAULT '',
    source        VARCHAR(32)     NOT NULL DEFAULT 'human',
    status        VARCHAR(16)     NOT NULL DEFAULT 'pending',
    before        JSONB,
    created_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    decided_at    TIMESTAMPTZ,
    decided_by    VARCHAR(100),
    decision_note TEXT,
    applied       BOOLEAN,
    apply_error   TEXT,
    CONSTRAINT config_proposals_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'failed'))
);
"""

CONFIG_PROPOSALS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_config_proposals_pending "
    "ON config_proposals(created_at DESC) WHERE status = 'pending';",
    "CREATE INDEX IF NOT EXISTS idx_config_proposals_engine "
    "ON config_proposals(engine, created_at DESC);",
]

EVIDENCE_RECORDS_TABLE = """
CREATE TABLE IF NOT EXISTS evidence_records (
    id              BIGSERIAL      PRIMARY KEY,
    evidence_id     VARCHAR(32)    NOT NULL UNIQUE,
    sensor_id       VARCHAR(128)   NOT NULL,
    boot_id         VARCHAR(32)    NOT NULL,
    engine          VARCHAR(64)    NOT NULL,
    seq_from        BIGINT,
    seq_to          BIGINT,
    event_time      TIMESTAMPTZ,
    build_version   VARCHAR(64)    NOT NULL DEFAULT '',
    config_version  VARCHAR(64)    NOT NULL DEFAULT '',
    feed_version    VARCHAR(64)    NOT NULL DEFAULT '',
    whitelist_version VARCHAR(64)  NOT NULL DEFAULT '',
    normalizer_version VARCHAR(64) NOT NULL DEFAULT '',
    features        JSONB          NOT NULL DEFAULT '{}'::jsonb,
    verdicts        JSONB          NOT NULL DEFAULT '[]'::jsonb,
    missing         JSONB          NOT NULL DEFAULT '[]'::jsonb,
    expired         BOOLEAN        NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);
"""

EVIDENCE_RECORDS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_evidence_engine_time "
    "ON evidence_records(engine, event_time DESC);",
    "CREATE INDEX IF NOT EXISTS idx_evidence_created "
    "ON evidence_records(created_at DESC);",
]

REPLAY_TRACES_TABLE = """
CREATE TABLE IF NOT EXISTS replay_traces (
    id              BIGSERIAL      PRIMARY KEY,
    trace_id        VARCHAR(32)    NOT NULL UNIQUE,
    input_type      VARCHAR(32)    NOT NULL DEFAULT 'features',
    input_count     INTEGER        NOT NULL DEFAULT 0,
    input_hash      VARCHAR(64)    NOT NULL DEFAULT '',
    order_key       VARCHAR(64)    NOT NULL DEFAULT '',
    tick_schedule   JSONB          NOT NULL DEFAULT '[]'::jsonb,
    warmup          JSONB          NOT NULL DEFAULT '{}'::jsonb,
    compat_snapshot JSONB          NOT NULL DEFAULT '{}'::jsonb,
    complete        BOOLEAN        NOT NULL DEFAULT TRUE,
    payload_engines JSONB          NOT NULL DEFAULT '[]'::jsonb,
    size_bytes      INTEGER        NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);
"""

REPLAY_TRACES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_replay_traces_hash ON replay_traces(input_hash);",
]

REPLAY_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS replay_runs (
    id                  BIGSERIAL    PRIMARY KEY,
    trace_id            VARCHAR(32)  NOT NULL,
    baseline_version    VARCHAR(128) NOT NULL,
    candidate_version   VARCHAR(128) NOT NULL,
    status              VARCHAR(16)  NOT NULL DEFAULT 'pending',
    baseline_result_hash VARCHAR(64),
    candidate_result_hash VARCHAR(64),
    non_comparable_reasons JSONB      NOT NULL DEFAULT '[]'::jsonb,
    comparable          BOOLEAN       NOT NULL DEFAULT FALSE,
    budget_exceeded     BOOLEAN       NOT NULL DEFAULT FALSE,
    budget_detail       JSONB         NOT NULL DEFAULT '{}'::jsonb,
    error               TEXT,
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT replay_runs_status_check
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'aborted'))
);
"""

REPLAY_RUNS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_replay_runs_trace "
    "ON replay_runs(trace_id, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_replay_runs_created ON replay_runs(created_at DESC);",
]

REPLAY_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS replay_results (
    id             BIGSERIAL      PRIMARY KEY,
    replay_run_id  BIGINT         NOT NULL
                   REFERENCES replay_runs(id) ON DELETE CASCADE,
    side           VARCHAR(16)    NOT NULL,
    engine         VARCHAR(64)    NOT NULL,
    result_hash    VARCHAR(64)    NOT NULL,
    observation_count INTEGER     NOT NULL DEFAULT 0,
    observations   JSONB          NOT NULL DEFAULT '[]'::jsonb,
    unsupported    JSONB          NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    CONSTRAINT replay_results_side_check CHECK (side IN ('baseline', 'candidate'))
);
"""

REPLAY_RESULTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_replay_results_run ON replay_results(replay_run_id, side);",
]

RESPONSE_ACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS response_actions (
    id                BIGSERIAL      PRIMARY KEY,
    proposal_id       BIGINT,
    target            VARCHAR(64)     NOT NULL,
    direction         VARCHAR(16)     NOT NULL DEFAULT 'input',
    ttl_seconds       INTEGER         NOT NULL,
    permanent         BOOLEAN         NOT NULL DEFAULT FALSE,
    state             VARCHAR(24)     NOT NULL DEFAULT 'requested',
    approved_hash     VARCHAR(64),
    base_version      VARCHAR(64),
    approved_by       VARCHAR(100),
    approved_at       TIMESTAMPTZ,
    rule_fingerprint  VARCHAR(64),
    rule_tag          VARCHAR(64),
    expire_at         TIMESTAMPTZ,
    mapping_confirmed_at TIMESTAMPTZ,
    idempotency_key   VARCHAR(128)    UNIQUE,
    attempt_count     INTEGER         NOT NULL DEFAULT 0,
    last_error        TEXT,
    created_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT response_actions_state_check CHECK (state IN (
        'requested', 'applying', 'active_verified', 'expiring',
        'expired_verified', 'removed_verified', 'failed', 'unknown'
    )),
    CONSTRAINT response_actions_direction_check
        CHECK (direction IN ('input', 'output', 'forward')),
    CONSTRAINT response_actions_ttl_check
        CHECK (permanent = FALSE AND ttl_seconds > 0)
);
"""

RESPONSE_ACTIONS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_response_actions_state "
    "ON response_actions(state, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_response_actions_target "
    "ON response_actions(target, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_response_actions_expire "
    "ON response_actions(expire_at) WHERE state = 'active_verified';",
]

RESPONSE_RECEIPTS_TABLE = """
CREATE TABLE IF NOT EXISTS response_receipts (
    id             BIGSERIAL    PRIMARY KEY,
    action_id      BIGINT       NOT NULL
                   REFERENCES response_actions(id) ON DELETE CASCADE,
    phase          VARCHAR(24)  NOT NULL,
    outcome        VARCHAR(24)  NOT NULL,
    detail         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    observed_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT response_receipts_outcome_check CHECK (outcome IN (
        'confirmed', 'absent', 'mismatch', 'unverified', 'error'
    ))
);
"""

RESPONSE_RECEIPTS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_response_receipts_action "
    "ON response_receipts(action_id, observed_at DESC);",
]

RESPONSE_PROPOSALS_TABLE = """
CREATE TABLE IF NOT EXISTS response_proposals (
    id                  BIGSERIAL      PRIMARY KEY,
    event_id            BIGINT,
    engine              VARCHAR(64)     NOT NULL DEFAULT '',
    source_ip           VARCHAR(64),
    evidence            JSONB          NOT NULL DEFAULT '{}'::jsonb,
    visibility_state    VARCHAR(16)    NOT NULL DEFAULT 'unknown',
    visibility_reasons  JSONB          NOT NULL DEFAULT '[]'::jsonb,
    target_mapping      JSONB          NOT NULL DEFAULT '{}'::jsonb,
    match_scope         JSONB          NOT NULL DEFAULT '{}'::jsonb,
    expected_assets     JSONB          NOT NULL DEFAULT '[]'::jsonb,
    unconfirmed_assets  JSONB          NOT NULL DEFAULT '[]'::jsonb,
    uncertainty         JSONB          NOT NULL DEFAULT '{}'::jsonb,
    ttl_seconds         INTEGER         NOT NULL,
    status              VARCHAR(16)     NOT NULL DEFAULT 'proposed',
    created_by          VARCHAR(64)     NOT NULL DEFAULT 'rules',
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT response_proposals_status_check
        CHECK (status IN ('proposed', 'approved', 'rejected', 'expired')),
    CONSTRAINT response_proposals_ttl_check CHECK (ttl_seconds > 0)
);
"""

RESPONSE_PROPOSALS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_response_proposals_src "
    "ON response_proposals(source_ip, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_response_proposals_status "
    "ON response_proposals(status, created_at DESC);",
]

FLUSH_RECEIPTS_TABLE = """
CREATE TABLE IF NOT EXISTS flush_receipts (
    flush_id UUID PRIMARY KEY,
    kind TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_flush_receipts_created ON flush_receipts(created_at);
"""

ALL_SCHEMAS = [
    FLUSH_RECEIPTS_TABLE,
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
    USERS_TABLE,
    AUDIT_LOG_TABLE,
    *AUDIT_LOG_INDEXES,
    CONFIG_PROPOSALS_TABLE,
    *CONFIG_PROPOSALS_INDEXES,
    EVIDENCE_RECORDS_TABLE,
    *EVIDENCE_RECORDS_INDEXES,
    REPLAY_TRACES_TABLE,
    *REPLAY_TRACES_INDEXES,
    REPLAY_RUNS_TABLE,
    *REPLAY_RUNS_INDEXES,
    REPLAY_RESULTS_TABLE,
    *REPLAY_RESULTS_INDEXES,
    RESPONSE_ACTIONS_TABLE,
    *RESPONSE_ACTIONS_INDEXES,
    RESPONSE_RECEIPTS_TABLE,
    *RESPONSE_RECEIPTS_INDEXES,
    RESPONSE_PROPOSALS_TABLE,
    *RESPONSE_PROPOSALS_INDEXES,
]
