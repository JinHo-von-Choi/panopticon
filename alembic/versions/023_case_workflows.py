"""사건 담당자와 인계 이력."""
from alembic import op
revision = "023_case_workflows"
down_revision = "022_business_reviews"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""
CREATE TABLE IF NOT EXISTS case_workflows (
    event_id BIGINT PRIMARY KEY,
    version BIGINT NOT NULL CHECK(version > 0 AND version <= 1000),
    owner VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK(status IN ('open','investigating','closed')),
    actor VARCHAR(255) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS case_history (
    event_id BIGINT NOT NULL REFERENCES case_workflows(event_id) ON DELETE CASCADE,
    version BIGINT NOT NULL CHECK(version > 0 AND version <= 1000),
    owner VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL CHECK(status IN ('open','investigating','closed')),
    note VARCHAR(1024) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(event_id,version)
);
    """)

def downgrade():
    op.execute("DROP TABLE IF EXISTS case_history")
    op.execute("DROP TABLE IF EXISTS case_workflows")
