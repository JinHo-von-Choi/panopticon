"""config_proposals: 설정 변경 제안 승인 큐.

Revision ID: 010_config_proposals
Revises: 009_users_and_audit
Create Date: 2026-10-05

계획서의 "읽기 / 제안 / 승인" 3역할에서 **승인** 단계를 실체화한다.
AI 는 제안만 기록하고(PR 03), 그 제안을 사람이 검토해 승인한 경우에만
검증을 통과한 경로로 설정에 반영된다.

이 테이블이 없으면 제안은 로그로만 남고 되돌릴 방법이 없다.
승인·거절·적용 결과를 남겨야 감사할 수 있다.
"""

from __future__ import annotations

from alembic import op

revision = "010_config_proposals"
down_revision = "009_users_and_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS config_proposals (
            id            SERIAL          PRIMARY KEY,
            engine        VARCHAR(64)     NOT NULL,
            params        JSONB           NOT NULL,
            reason        TEXT            NOT NULL DEFAULT '',
            source        VARCHAR(32)     NOT NULL DEFAULT 'human',
            status        VARCHAR(16)     NOT NULL DEFAULT 'pending',
            -- 승인 시점의 현재 설정 (되돌리기 근거)
            before        JSONB,
            created_at    TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
            decided_at    TIMESTAMPTZ,
            decided_by    VARCHAR(100),
            decision_note TEXT,
            -- 승인 후 실제 적용에 성공했는지
            applied       BOOLEAN,
            apply_error   TEXT,
            CONSTRAINT config_proposals_status_check
                CHECK (status IN ('pending', 'approved', 'rejected', 'failed'))
        )
    """)
    # 대기 중인 제안만 반복 조회된다
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_config_proposals_pending
        ON config_proposals(created_at DESC) WHERE status = 'pending'
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_config_proposals_engine
        ON config_proposals(engine, created_at DESC)
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS config_proposals")
