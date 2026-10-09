"""개인별 계정 저장소."""
from alembic import op
revision='027_user_accounts'
down_revision='026_event_group_indexes'
branch_labels=None
depends_on=None


def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS user_accounts (
    id UUID PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE CHECK(username ~ '^[a-z0-9_.-]{1,64}$'),
    password_hash TEXT NOT NULL,
    role VARCHAR(16) NOT NULL CHECK(role IN ('viewer','analyst','admin')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK(version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by VARCHAR(255) NOT NULL
);""")


def downgrade():
    op.execute('DROP TABLE IF EXISTS user_accounts')
