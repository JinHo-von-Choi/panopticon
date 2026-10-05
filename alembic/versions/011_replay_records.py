"""evidence / trace / replay_run 기록 (계획서 1장, PR 12).

Revision ID: 011_replay_records
Revises: 010_config_proposals
Create Date: 2026-10-06

"기존/후보 예외를 같은 입력으로 비교한다" 를 하려면 세 가지가 남아야 한다.

1. **Evidence** — 그 경보가 *무엇을 보고 무엇에 근거해* 나왔는가
2. **Trace**  — 그 판정을 되풀이할 수 있는 **동일 입력**
3. **ReplayRun** — 같은 입력에 두 버전을 돌린 **결과 해시와 비교 불가 사유**

이 셋 중 하나라도 없으면 비교는 불가능하고, 비교 불가능한 것을 가능해 보이게
만드는 것이 이 계획서가 가장 경계하는 일이다. 그래서 비교 불가 사유를
`replay_runs` 의 컬럼으로 둔다 — 사유 없는 비교는 만들지 않는다.

payload 엔진을 위한 원본 패킷은 저장하지 않는다. 근거에 필요한 값만 저장한다
(계획서: "패킷별 영구 기록 대신 필요한 근거만 저장한다").
"""

from __future__ import annotations

from alembic import op

revision = "011_replay_records"
down_revision = "010_config_proposals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS evidence_records (
            id              BIGSERIAL      PRIMARY KEY,
            evidence_id     VARCHAR(32)    NOT NULL UNIQUE,
            sensor_id       VARCHAR(128)   NOT NULL,
            boot_id         VARCHAR(32)    NOT NULL,
            engine          VARCHAR(64)    NOT NULL,
            -- 이 판정이 읽은 입력 구간 (Trace 와 이어진다)
            seq_from        BIGINT,
            seq_to          BIGINT,
            event_time      TIMESTAMPTZ,
            -- 재현에 필요한 버전 지문
            build_version   VARCHAR(64)    NOT NULL DEFAULT '',
            config_version  VARCHAR(64)    NOT NULL DEFAULT '',
            feed_version    VARCHAR(64)    NOT NULL DEFAULT '',
            whitelist_version VARCHAR(64)  NOT NULL DEFAULT '',
            normalizer_version VARCHAR(64) NOT NULL DEFAULT '',
            -- 실제로 사용한 특징값과 조건별 판정
            features        JSONB          NOT NULL DEFAULT '{}'::jsonb,
            verdicts        JSONB          NOT NULL DEFAULT '[]'::jsonb,
            -- 누락·만료 상태. 재현 불가의 이유가 된다
            missing         JSONB          NOT NULL DEFAULT '[]'::jsonb,
            expired         BOOLEAN        NOT NULL DEFAULT FALSE,
            created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_engine_time
        ON evidence_records(engine, event_time DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_evidence_created
        ON evidence_records(created_at DESC)
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS replay_traces (
            id              BIGSERIAL      PRIMARY KEY,
            trace_id        VARCHAR(32)    NOT NULL UNIQUE,
            input_type      VARCHAR(32)    NOT NULL DEFAULT 'features',
            input_count     INTEGER        NOT NULL DEFAULT 0,
            -- 입력 해시: 같은 입력이 같은지 확인할 수 있어야 한다
            input_hash      VARCHAR(64)    NOT NULL DEFAULT '',
            -- 되풀이 가능성: 순서, tick 일정, 워밍업
            order_key       VARCHAR(64)    NOT NULL DEFAULT '',
            tick_schedule   JSONB          NOT NULL DEFAULT '[]'::jsonb,
            warmup          JSONB          NOT NULL DEFAULT '{}'::jsonb,
            compat_snapshot JSONB          NOT NULL DEFAULT '{}'::jsonb,
            complete        BOOLEAN        NOT NULL DEFAULT TRUE,
            -- 원본이 없어 재현할 수 없는 엔진 (payload 계열)
            payload_engines JSONB          NOT NULL DEFAULT '[]'::jsonb,
            size_bytes      INTEGER        NOT NULL DEFAULT 0,
            created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_replay_traces_hash
        ON replay_traces(input_hash)
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS replay_runs (
            id                  BIGSERIAL    PRIMARY KEY,
            trace_id            VARCHAR(32)  NOT NULL,
            baseline_version    VARCHAR(128) NOT NULL,
            candidate_version   VARCHAR(128) NOT NULL,
            status              VARCHAR(16)  NOT NULL DEFAULT 'pending',
            baseline_result_hash VARCHAR(64),
            candidate_result_hash VARCHAR(64),
            -- 비교 불가 사유. 이게 없으면 "비교했다"고 말할 수 없다
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
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_replay_runs_trace
        ON replay_runs(trace_id, created_at DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_replay_runs_created
        ON replay_runs(created_at DESC)
    """)

    # 결과 본문은 격리된 별도 테이블에 저장한다.
    # 운영 events 테이블에 쓰는 것은 금지되므로, 리플레이 결과는 여기만 쓴다.
    op.execute("""
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
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_replay_results_run
        ON replay_results(replay_run_id, side)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS replay_results")
    op.execute("DROP TABLE IF EXISTS replay_runs")
    op.execute("DROP TABLE IF EXISTS replay_traces")
    op.execute("DROP TABLE IF EXISTS evidence_records")
