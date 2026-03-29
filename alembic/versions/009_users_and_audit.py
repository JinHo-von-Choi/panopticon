"""users 및 audit_log 테이블 생성.

Revision ID: 009_users_and_audit
Revises: 008_events_monthly_partitioning
Create Date: 2026-03-29

users: 다중 사용자 인증 지원을 위한 사용자 테이블.
audit_log: API 호출에 대한 감사 추적 테이블.
"""

from __future__ import annotations

from alembic import op

revision      = "009_users_and_audit"
down_revision = "008_events_monthly_partitioning"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL          PRIMARY KEY,
            username        VARCHAR(100)    UNIQUE NOT NULL,
            password_hash   VARCHAR(200)    NOT NULL,
            role            VARCHAR(20)     NOT NULL DEFAULT 'viewer',
            created_at      TIMESTAMPTZ     DEFAULT NOW(),
            last_login      TIMESTAMPTZ
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          SERIAL          PRIMARY KEY,
            user_id     VARCHAR(100),
            action      VARCHAR(50)     NOT NULL,
            resource    VARCHAR(200),
            details     JSONB,
            ip          VARCHAR(45),
            created_at  TIMESTAMPTZ     DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log (created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log (user_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS users")
