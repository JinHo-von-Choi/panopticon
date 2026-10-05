"""response_actions: 확인 가능한 만료 복구 (계획서 2장, PR 13).

Revision ID: 012_response_actions
Revises: 011_replay_records
Create Date: 2026-10-06

    "ResponseAction 은 requested → applying → active_verified → expiring →
     expired_verified, 수동 취소의 removed_verified 와 failed/unknown 을 둔다."
    "unknown 을 성공이나 해제로 표시하지 않는다."
    "idempotency_key 로 중복을 막고 재시도해도 최초 expire_at 을 연장하지 않는다."

왜 상태가 DB 행 하나에 필요한가

    "적용 의도를 먼저 내용 저장하고 OS 적용 → 조회 확인 → 영수증 기록으로
     이어간다. DB 와 OS 사이의 원자성을 가정하지 않는다."

즉 **의도(intent) 와 사실(fact) 이 다른 행에 다른 시점에 남는다.** 그래서
`requested` 상태에서 프로세스가 죽어도 "무엇을 하려 했는가" 는 남고,
재시작 조정기가 그것을 OS 와 대조한다. 이 구분을 없애면 아무도 모르는 규칙이
패킷 위에 남는다.
"""

from __future__ import annotations

from alembic import op

revision = "012_response_actions"
down_revision = "011_replay_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (
            id                BIGSERIAL      PRIMARY KEY,
            proposal_id       BIGINT,
            -- 대상·방향·TTL 만 실행기로 전달된다. 웹 은 실행 권한이 없다
            target            VARCHAR(64)     NOT NULL,
            direction         VARCHAR(16)     NOT NULL DEFAULT 'input',
            ttl_seconds       INTEGER         NOT NULL,
            -- 영구 조치 금지 (계획서: "영구 조치 금지")
            permanent         BOOLEAN         NOT NULL DEFAULT FALSE,
            -- 상태 기계
            state             VARCHAR(24)     NOT NULL DEFAULT 'requested',
            -- 승인 시 고정한 값. 바뀌면 409
            approved_hash     VARCHAR(64),
            base_version      VARCHAR(64),
            approved_by       VARCHAR(100),
            approved_at       TIMESTAMPTZ,
            -- 적용 후 확인된 사실
            rule_fingerprint  VARCHAR(64),
            rule_tag          VARCHAR(64),
            -- 만료는 최초 확정값. 재시도해도 연장하지 않는다
            expire_at         TIMESTAMPTZ,
            -- 중복 방지
            idempotency_key   VARCHAR(128)    UNIQUE,
            attempt_count     INTEGER         NOT NULL DEFAULT 0,
            -- 사유 없는 성공을 만들지 않기 위한 원장
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
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_actions_state
        ON response_actions(state, created_at DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_actions_target
        ON response_actions(target, created_at DESC)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_actions_expire
        ON response_actions(expire_at) WHERE state = 'active_verified'
    """)

    # 영수증 — "확인했다" 의 근거. 감사 이력 90일 보관 대상
    op.execute("""
        CREATE TABLE IF NOT EXISTS response_receipts (
            id             BIGSERIAL    PRIMARY KEY,
            action_id      BIGINT       NOT NULL
                           REFERENCES response_actions(id) ON DELETE CASCADE,
            phase          VARCHAR(24)  NOT NULL,
            -- 조회 확인 결과. 'unknown' 도 값으로 남긴다
            outcome        VARCHAR(24)  NOT NULL,
            detail         JSONB        NOT NULL DEFAULT '{}'::jsonb,
            observed_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            CONSTRAINT response_receipts_outcome_check CHECK (outcome IN (
                'confirmed', 'absent', 'mismatch', 'unverified', 'error'
            ))
        )
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_receipts_action
        ON response_receipts(action_id, observed_at DESC)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS response_receipts")
    op.execute("DROP TABLE IF EXISTS response_actions")
