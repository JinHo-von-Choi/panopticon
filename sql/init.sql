-- NetWatcher PostgreSQL 초기화 스크립트
-- 작성자: 최진호
-- 작성일: 2026-02-20
-- 설명: SQLite에서 PostgreSQL 마이그레이션을 위한 DB, 스키마, 테이블 생성

-- ============================================================
-- 1. 데이터베이스 생성 (psql에서 실행, 또는 superuser 권한 필요)
--    이미 존재하면 무시
-- ============================================================

-- 사용자 생성 (이미 존재하면 스킵)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'home') THEN
        -- 비밀번호를 실제 값으로 변경할 것:
        -- ALTER ROLE home WITH PASSWORD 'your_actual_password';
        CREATE ROLE home WITH LOGIN PASSWORD 'CHANGE_ME';
    END IF;
END
$$;

-- 데이터베이스 생성은 트랜잭션 내에서 실행 불가하므로 별도 실행 필요:
-- CREATE DATABASE netwatcher OWNER home ENCODING 'UTF8' LC_COLLATE 'ko_KR.UTF-8' LC_CTYPE 'ko_KR.UTF-8';
-- 또는 locale이 없는 환경:
-- CREATE DATABASE netwatcher OWNER home ENCODING 'UTF8';

-- ============================================================
-- 2. 스키마 생성
-- ============================================================
CREATE SCHEMA IF NOT EXISTS netwatcher;

ALTER SCHEMA netwatcher OWNER TO home;

-- 기본 검색 경로 설정
ALTER ROLE home SET search_path TO netwatcher, public;

-- ============================================================
-- 3. 확장 모듈
-- ============================================================
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- LIKE/ILIKE 검색 성능 향상

-- ============================================================
-- 4. 테이블 생성
-- ============================================================

-- ------------------------------------------------------------
-- 4-1. events: 탐지 이벤트 저장
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS netwatcher.events (
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

COMMENT ON TABLE  netwatcher.events              IS '탐지 엔진이 생성한 보안 이벤트';
COMMENT ON COLUMN netwatcher.events.engine        IS '이벤트를 생성한 탐지 엔진 이름';
COMMENT ON COLUMN netwatcher.events.severity      IS '심각도: INFO, WARNING, CRITICAL';
COMMENT ON COLUMN netwatcher.events.metadata      IS '엔진별 추가 메타데이터 (JSON)';
COMMENT ON COLUMN netwatcher.events.packet_info   IS '원본 패킷 요약 정보 (JSON)';
COMMENT ON COLUMN netwatcher.events.resolved      IS '이벤트 해결 여부';

-- ------------------------------------------------------------
-- 4-2. devices: 네트워크 디바이스 목록
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS netwatcher.devices (
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

COMMENT ON TABLE  netwatcher.devices              IS '네트워크에서 탐지된 디바이스 목록';
COMMENT ON COLUMN netwatcher.devices.mac_address   IS 'MAC 주소 (유니크 키)';
COMMENT ON COLUMN netwatcher.devices.is_known      IS '관리자가 등록한 알려진 디바이스 여부';
COMMENT ON COLUMN netwatcher.devices.open_ports    IS '탐지된 열린 포트 목록 (JSON 배열)';
COMMENT ON COLUMN netwatcher.devices.os_hint       IS 'OS 핑거프린팅 추정값';

-- ------------------------------------------------------------
-- 4-3. custom_blocklist: 사용자 정의 차단 목록
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS netwatcher.custom_blocklist (
    id          BIGSERIAL       PRIMARY KEY,
    entry_type  VARCHAR(16)     NOT NULL CHECK (entry_type IN ('ip', 'domain')),
    value       VARCHAR(512)    NOT NULL,
    source      VARCHAR(128)    NOT NULL DEFAULT 'Custom',
    notes       TEXT            NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_blocklist_type_value UNIQUE (entry_type, value)
);

COMMENT ON TABLE netwatcher.custom_blocklist IS '사용자 정의 IP/도메인 차단 목록';

-- ------------------------------------------------------------
-- 4-4. traffic_stats: 분당 트래픽 통계
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS netwatcher.traffic_stats (
    id            BIGSERIAL       PRIMARY KEY,
    timestamp     TIMESTAMPTZ     NOT NULL,
    total_packets BIGINT          NOT NULL DEFAULT 0,
    total_bytes   BIGINT          NOT NULL DEFAULT 0,
    tcp_count     BIGINT          NOT NULL DEFAULT 0,
    udp_count     BIGINT          NOT NULL DEFAULT 0,
    arp_count     BIGINT          NOT NULL DEFAULT 0,
    dns_count     BIGINT          NOT NULL DEFAULT 0
);

COMMENT ON TABLE netwatcher.traffic_stats IS '분 단위 프로토콜별 트래픽 집계';

-- ============================================================
-- 5. 인덱스
-- ============================================================

-- events 인덱스
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON netwatcher.events (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_engine
    ON netwatcher.events (engine);

CREATE INDEX IF NOT EXISTS idx_events_severity
    ON netwatcher.events (severity);

CREATE INDEX IF NOT EXISTS idx_events_resolved
    ON netwatcher.events (resolved)
    WHERE resolved = FALSE;              -- 미해결 이벤트만 partial index

CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON netwatcher.events (source_ip)
    WHERE source_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_events_search_trgm
    ON netwatcher.events USING gin (title gin_trgm_ops);  -- LIKE 검색 가속

-- devices 인덱스
CREATE INDEX IF NOT EXISTS idx_devices_mac
    ON netwatcher.devices (mac_address);

CREATE INDEX IF NOT EXISTS idx_devices_ip
    ON netwatcher.devices (ip_address)
    WHERE ip_address IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_last_seen
    ON netwatcher.devices (last_seen DESC);

-- custom_blocklist 인덱스
CREATE INDEX IF NOT EXISTS idx_blocklist_type
    ON netwatcher.custom_blocklist (entry_type);

CREATE INDEX IF NOT EXISTS idx_blocklist_value
    ON netwatcher.custom_blocklist (value);

-- traffic_stats 인덱스
CREATE INDEX IF NOT EXISTS idx_traffic_stats_ts
    ON netwatcher.traffic_stats (timestamp DESC);

-- ============================================================
-- 6. 권한 부여
-- ============================================================
GRANT USAGE ON SCHEMA netwatcher TO home;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA netwatcher TO home;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA netwatcher TO home;

-- 향후 생성되는 객체에 대한 기본 권한
ALTER DEFAULT PRIVILEGES IN SCHEMA netwatcher
    GRANT ALL PRIVILEGES ON TABLES TO home;

ALTER DEFAULT PRIVILEGES IN SCHEMA netwatcher
    GRANT ALL PRIVILEGES ON SEQUENCES TO home;
