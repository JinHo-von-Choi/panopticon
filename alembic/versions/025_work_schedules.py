"""승인 작업 일정과 사건 연결."""
from alembic import op
revision = "025_work_schedules"
down_revision = "024_business_review_history"
branch_labels = None
depends_on = None

def upgrade():
    op.execute("""
CREATE TABLE IF NOT EXISTS work_schedules (
    id UUID PRIMARY KEY,
    fingerprint CHAR(64) NOT NULL UNIQUE,
    content JSONB NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL CHECK(ends_at > starts_at),
    actor VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1 CHECK(version IN (1,2)),
    revoked_at TIMESTAMPTZ,
    revoked_by VARCHAR(255),
    revocation_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_work_schedules_scope ON work_schedules
    ((content->>'source_ip'),(content->>'dest_ip'),starts_at,ends_at);
CREATE TABLE IF NOT EXISTS event_work_links (
    event_id BIGINT PRIMARY KEY,
    schedule_id UUID NOT NULL REFERENCES work_schedules(id),
    version BIGINT NOT NULL CHECK(version > 0),
    actor VARCHAR(255) NOT NULL,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
    """)

def downgrade():
    op.execute("DROP TABLE IF EXISTS event_work_links")
    op.execute("DROP TABLE IF EXISTS work_schedules")
