"""레거시 users 테이블 폐기.

다중 사용자 인증은 `user_accounts` 가 담당한다. `users` 는 아무 코드도
읽지 않아 두 정의(스키마·마이그레이션)만 남아 있었다.
"""

from alembic import op

revision = "044_drop_legacy_users"
down_revision = "043_analysis_experiences"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE IF EXISTS users")


def downgrade() -> None:
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
