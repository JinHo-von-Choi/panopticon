"""통계·디바이스 스냅샷의 commit 응답 유실 후 중복 가산 방지."""

from alembic import op

revision = "015_flush_receipts"
down_revision = "014_action_mapping_freshness"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE IF NOT EXISTS flush_receipts (
        flush_id UUID PRIMARY KEY,
        kind TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )""")
    op.execute("CREATE INDEX IF NOT EXISTS idx_flush_receipts_created ON flush_receipts(created_at)")


def downgrade():
    op.execute("DROP TABLE IF EXISTS flush_receipts")
