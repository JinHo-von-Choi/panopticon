"""업무 판정의 당시 근거와 적용 범위 이력."""
from alembic import op
revision = "024_business_review_history"
down_revision = "023_case_workflows"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""
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
INSERT INTO business_review_history
    SELECT event_id,version,decision,note,actor,scope,reviewed_at,expires_at FROM business_reviews
    ON CONFLICT DO NOTHING;
    """)

def downgrade():
    op.execute("DROP TABLE IF EXISTS business_review_history")
