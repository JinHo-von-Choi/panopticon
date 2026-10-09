"""NetWatcher용 PostgreSQL 스키마 정의."""

EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL       PRIMARY KEY,
    tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
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
    "CREATE INDEX IF NOT EXISTS idx_events_tenant_id ON events USING btree(tenant_id);",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_events_engine ON events(engine);",
    "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);",
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip) WHERE source_ip IS NOT NULL;",
    "CREATE INDEX IF NOT EXISTS idx_events_mitre ON events(mitre_attack_id) WHERE mitre_attack_id IS NOT NULL;",
]

DEVICES_TABLE = """
CREATE TABLE IF NOT EXISTS devices (
    id               BIGSERIAL    PRIMARY KEY,
    tenant_id        UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
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
    host_labels      JSONB        NOT NULL DEFAULT '[]',
    context_profile  JSONB        NOT NULL DEFAULT '{}',
    context_version  BIGINT       NOT NULL DEFAULT 0,
    ip_mapping_version BIGINT     NOT NULL DEFAULT 0
);
"""

DEVICES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_devices_tenant_id ON devices USING btree(tenant_id);",
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
    tenant_id         UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
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
    "CREATE INDEX IF NOT EXISTS idx_incidents_tenant_id ON incidents USING btree(tenant_id);",
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
    tenant_id   UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    user_id     VARCHAR(100),
    action      VARCHAR(50)     NOT NULL,
    resource    VARCHAR(200),
    details     JSONB,
    ip          VARCHAR(45),
    created_at  TIMESTAMPTZ     DEFAULT NOW(),
    prev_hash   VARCHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    entry_hash  VARCHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
);
"""

AUDIT_LOG_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log USING btree(tenant_id);",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_request ON audit_log((details->>'request_id'), created_at, id);",
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
    validation_runs JSONB NOT NULL DEFAULT '{}'::jsonb,
    applied       BOOLEAN,
    apply_error   TEXT,
    sensor_id     VARCHAR(128),
    sensor_owner  UUID,
    source_version VARCHAR(64),
    CONSTRAINT config_proposals_origin_check CHECK (
        (sensor_id IS NULL AND sensor_owner IS NULL AND source_version IS NULL)
        OR (sensor_id IS NOT NULL AND length(sensor_id)>0 AND sensor_owner IS NOT NULL
            AND source_version IS NOT NULL AND source_version ~ '^[a-f0-9]{64}$')),
    CONSTRAINT config_proposals_status_check
        CHECK (status IN ('pending', 'approved', 'rejected', 'failed'))
);
"""

CONFIG_PROPOSALS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_config_proposals_pending "
    "ON config_proposals(created_at DESC) WHERE status = 'pending';",
    "CREATE INDEX IF NOT EXISTS idx_config_proposals_engine "
    "ON config_proposals(engine, created_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_config_proposals_sensor "
    "ON config_proposals(sensor_id, created_at DESC, id DESC);",
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

EVENT_INGEST_TABLE = """
CREATE TABLE IF NOT EXISTS event_ingest (
    ingest_id UUID PRIMARY KEY,
    event_id BIGINT NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_ingest_timestamp ON event_ingest(event_timestamp);
"""

FLUSH_RECEIPTS_TABLE = """
CREATE TABLE IF NOT EXISTS flush_receipts (
    flush_id UUID PRIMARY KEY,
    kind TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_flush_receipts_created ON flush_receipts(created_at);
"""

ASSET_CONTEXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_context_history (
    id BIGSERIAL PRIMARY KEY,
    mac_address MACADDR NOT NULL,
    version BIGINT NOT NULL,
    profile JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mac_address, version)
);
CREATE OR REPLACE FUNCTION bump_device_mapping() RETURNS trigger AS $$
BEGIN
    IF NEW.ip_address IS DISTINCT FROM OLD.ip_address THEN
        NEW.ip_mapping_version := OLD.ip_mapping_version + 1;
    ELSE
        NEW.ip_mapping_version := OLD.ip_mapping_version;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS devices_mapping_generation ON devices;
CREATE TRIGGER devices_mapping_generation BEFORE UPDATE ON devices
FOR EACH ROW EXECUTE FUNCTION bump_device_mapping();
"""

EVE_SCHEMA = """
CREATE TABLE IF NOT EXISTS eve_checkpoints (
    sensor_id VARCHAR(64) NOT NULL,
    source_id VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0,
    state JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(sensor_id, source_id)
);
CREATE TABLE IF NOT EXISTS eve_records (
    ingest_id UUID PRIMARY KEY,
    sensor_id VARCHAR(64) NOT NULL,
    source_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    observed_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    record JSONB NOT NULL,
    event_id BIGINT,
    accounted_bytes BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_eve_records_flow ON eve_records(sensor_id, source_id, (record->>'flow_id'));
CREATE INDEX IF NOT EXISTS idx_eve_records_received ON eve_records(received_at);
CREATE INDEX IF NOT EXISTS idx_eve_records_source_received ON eve_records(sensor_id, source_id, received_at);
CREATE INDEX IF NOT EXISTS idx_eve_records_event ON eve_records(event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_eve_records_alert_window ON eve_records(sensor_id,source_id,observed_at)
    WHERE event_type='alert';
CREATE TABLE IF NOT EXISTS eve_storage_usage (
    sensor_id VARCHAR(64) NOT NULL,
    source_id VARCHAR(64) NOT NULL,
    record_count BIGINT NOT NULL DEFAULT 0 CHECK(record_count >= 0),
    accounted_bytes BIGINT NOT NULL DEFAULT 0 CHECK(accounted_bytes >= 0),
    PRIMARY KEY(sensor_id, source_id)
);
"""

BUSINESS_REVIEWS_SCHEMA = """
CREATE TABLE IF NOT EXISTS business_reviews (
    event_id BIGINT PRIMARY KEY,
    version BIGINT NOT NULL CHECK(version > 0),
    decision VARCHAR(32) NOT NULL,
    note TEXT NOT NULL,
    actor VARCHAR(255) NOT NULL,
    scope JSONB NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);
"""

CASE_WORKFLOWS_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_workflows (
    event_id BIGINT PRIMARY KEY,
    version BIGINT NOT NULL CHECK(version > 0 AND version <= 1000),
    owner VARCHAR(128) NOT NULL,
    owner_id UUID REFERENCES user_accounts(id),
    status VARCHAR(16) NOT NULL CHECK(status IN ('open','investigating','closed')),
    actor VARCHAR(255) NOT NULL,
    actor_id UUID REFERENCES user_accounts(id),
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS case_history (
    event_id BIGINT NOT NULL REFERENCES case_workflows(event_id) ON DELETE CASCADE,
    version BIGINT NOT NULL CHECK(version > 0 AND version <= 1000),
    owner VARCHAR(128) NOT NULL,
    owner_id UUID REFERENCES user_accounts(id),
    status VARCHAR(16) NOT NULL CHECK(status IN ('open','investigating','closed')),
    note VARCHAR(1024) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    actor_id UUID REFERENCES user_accounts(id),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(event_id,version)
);
CREATE INDEX IF NOT EXISTS case_workflows_owner_id_idx ON case_workflows(owner_id);
"""

BUSINESS_REVIEW_HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS business_review_history (
    event_id BIGINT NOT NULL REFERENCES business_reviews(event_id) ON DELETE CASCADE,
    version BIGINT NOT NULL CHECK(version > 0),
    decision VARCHAR(32) NOT NULL,
    note TEXT NOT NULL,
    actor VARCHAR(255) NOT NULL,
    scope JSONB NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY(event_id,version)
);
"""

WORK_SCHEDULES_SCHEMA = """
CREATE TABLE IF NOT EXISTS work_schedules (
    id UUID PRIMARY KEY,
    fingerprint CHAR(64) NOT NULL UNIQUE,
    content JSONB NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL CHECK(ends_at > starts_at),
    actor VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1 CHECK(version IN (1,2)),
    revoked_at TIMESTAMPTZ,
    revoked_by VARCHAR(255),
    revocation_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_work_schedules_scope ON work_schedules
    ((content->>'source_ip'),(content->>'dest_ip'),starts_at,ends_at);
CREATE TABLE IF NOT EXISTS event_work_links (
    event_id BIGINT PRIMARY KEY,
    schedule_id UUID NOT NULL REFERENCES work_schedules(id),
    version BIGINT NOT NULL CHECK(version > 0),
    actor VARCHAR(255) NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

USER_ACCOUNTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS user_accounts (
    id UUID PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE CHECK(username ~ '^[a-z0-9_.-]{1,64}$'),
    password_hash TEXT NOT NULL,
    role VARCHAR(16) NOT NULL CHECK(role IN ('viewer','analyst','admin')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK(version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by VARCHAR(255) NOT NULL
);
"""

OIDC_IDENTITIES_SCHEMA = """
CREATE TABLE IF NOT EXISTS oidc_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    issuer VARCHAR(512) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    UNIQUE(issuer,subject),
    UNIQUE(user_id,issuer)
);
"""

OIDC_LOGIN_REQUESTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS oidc_login_requests (
    state_hash VARCHAR(64) PRIMARY KEY,
    browser_hash VARCHAR(64) NOT NULL,
    protected TEXT NOT NULL CHECK(length(protected) <= 4096),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oidc_login_expiry ON oidc_login_requests(expires_at);
"""

EXECUTION_CLAIMS_SCHEMA = """
CREATE TABLE IF NOT EXISTS response_execution_bindings (
    action_id BIGINT PRIMARY KEY REFERENCES response_actions(id),
    actor_id UUID NOT NULL REFERENCES user_accounts(id),
    actor_version BIGINT NOT NULL CHECK(actor_version > 0),
    device_id BIGINT NOT NULL REFERENCES devices(id),
    mapping_version BIGINT NOT NULL CHECK(mapping_version >= 0),
    scope JSONB NOT NULL,
    reason VARCHAR(512) NOT NULL CHECK(length(reason) > 0),
    approval_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS response_execution_claims (
    action_id BIGINT NOT NULL REFERENCES response_actions(id),
    operation VARCHAR(8) NOT NULL CHECK(operation IN ('apply','remove')),
    request_hash VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK(status IN ('prepared','completed')),
    result JSONB,
    prepared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY(action_id, operation),
    CHECK((status = 'prepared' AND result IS NULL AND completed_at IS NULL)
       OR (status = 'completed' AND result IS NOT NULL AND completed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_execution_claims_prepared ON response_execution_claims(prepared_at);
"""

SENSOR_RUNTIME_STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sensor_runtime_state (
    sensor_id VARCHAR(128) PRIMARY KEY,
    owner UUID NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    stopped BOOLEAN NOT NULL DEFAULT FALSE,
    snapshot JSONB NOT NULL DEFAULT '{}',
    CHECK(length(sensor_id) > 0),
    CHECK(jsonb_typeof(snapshot) = 'object'),
    CHECK(octet_length(snapshot::text) <= 65536)
);
"""

EVENT_STREAM_NOTIFICATION_SCHEMA = """
CREATE OR REPLACE FUNCTION notify_committed_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_catalog.pg_notify('nw_events_' || pg_catalog.md5(TG_TABLE_SCHEMA),
        pg_catalog.json_build_object('id',NEW.id,'timestamp',NEW.timestamp)::text);
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS events_stream_notify ON events;
CREATE TRIGGER events_stream_notify AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION notify_committed_event();
"""

SENSOR_CONTROL_CLAIMS_SCHEMA = """
CREATE TABLE IF NOT EXISTS sensor_control_claims (
    request_id UUID PRIMARY KEY,
    sensor_id VARCHAR(128) NOT NULL,
    owner UUID NOT NULL,
    actor_id UUID NOT NULL,
    command_hash VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'prepared' CHECK(status IN ('prepared','completed')),
    result JSONB,
    prepared_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ,
    CHECK((status='prepared' AND result IS NULL AND completed_at IS NULL)
       OR (status='completed' AND result IS NOT NULL AND completed_at IS NOT NULL)),
    CHECK(result IS NULL OR (jsonb_typeof(result)='object' AND octet_length(result::text)<=65536))
);
"""

TENANT_TABLES = ("events", "devices", "incidents", "audit_log")

# CASE는 system 값을 UUID로 변환하지 않는다. 미설정·빈 컨텍스트는 접근을 거절한다.
TENANT_RLS_SCHEMAS = [
    f"""
ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_{table} ON {table};
CREATE POLICY tenant_isolation_{table} ON {table}
    USING (
        CASE WHEN current_setting('app.current_tenant_id', true) = 'system'
             THEN TRUE
             ELSE tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        END
    );
"""
    for table in TENANT_TABLES
]

from netwatcher.storage.account_access import ACCOUNT_LOCK_FUNCTION_SQL
from netwatcher.storage.sensor_claim_retention import SENSOR_CLAIM_RETENTION_SQL

ALL_SCHEMAS = [
    SENSOR_CONTROL_CLAIMS_SCHEMA,
    SENSOR_RUNTIME_STATE_SCHEMA,
    USER_ACCOUNTS_SCHEMA,
    ACCOUNT_LOCK_FUNCTION_SQL,
    OIDC_IDENTITIES_SCHEMA,
    OIDC_LOGIN_REQUESTS_SCHEMA,
    WORK_SCHEDULES_SCHEMA,
    CASE_WORKFLOWS_SCHEMA,
    BUSINESS_REVIEWS_SCHEMA,
    BUSINESS_REVIEW_HISTORY_SCHEMA,
    EVE_SCHEMA,
    FLUSH_RECEIPTS_TABLE,
    EVENT_INGEST_TABLE,
    EVENTS_TABLE,
    *EVENTS_INDEXES,
    DEVICES_TABLE,
    ASSET_CONTEXT_SCHEMA,
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
    SENSOR_CLAIM_RETENTION_SQL,
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
    EXECUTION_CLAIMS_SCHEMA,
    *RESPONSE_RECEIPTS_INDEXES,
    RESPONSE_PROPOSALS_TABLE,
    *RESPONSE_PROPOSALS_INDEXES,
    EVENT_STREAM_NOTIFICATION_SCHEMA,
    *TENANT_RLS_SCHEMAS,
]
