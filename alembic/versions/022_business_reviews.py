"""사건별 업무 판정과 적용 범위."""
from alembic import op

revision = "022_business_reviews"
down_revision = "021_eve_storage_budget"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
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
    """)


def downgrade():
    op.execute("DROP TABLE IF EXISTS business_reviews")
