"""감사 로그 무결성 체인 컬럼."""

from alembic import op
import sqlalchemy as sa

revision = "039_audit_log_hash_chain"
down_revision = "038_multi_tenancy_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name in ("prev_hash", "entry_hash"):
        op.add_column("audit_log", sa.Column(name, sa.String(64), nullable=False,
                                           server_default="0" * 64))


def downgrade() -> None:
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "prev_hash")
