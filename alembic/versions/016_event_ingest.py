"""대표 경보의 안정적 ingest 식별자와 재시도 ID 복구."""
from alembic import op

revision = "016_event_ingest"
down_revision = "015_flush_receipts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS event_ingest (
        ingest_id UUID PRIMARY KEY,
        event_id BIGINT NOT NULL,
        event_timestamp TIMESTAMPTZ NOT NULL
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_event_ingest_timestamp ON event_ingest(event_timestamp)")


def downgrade():
    op.execute("DROP TABLE IF EXISTS event_ingest")
