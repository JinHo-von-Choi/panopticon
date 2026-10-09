"""핵심 테이블 테넌트 식별자와 행 격리 정책."""

from alembic import op

from netwatcher.storage.schemas import TENANT_RLS_SCHEMAS, TENANT_TABLES

revision = "038_multi_tenancy_rls"
down_revision = "037_sensor_claim_retention"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(
            f"ALTER TABLE {table} ADD COLUMN tenant_id UUID NOT NULL "
            "DEFAULT '00000000-0000-0000-0000-000000000000'"
        )
        op.execute(f"CREATE INDEX idx_{table}_tenant_id ON {table} USING btree(tenant_id)")
    for statement in TENANT_RLS_SCHEMAS:
        op.execute(statement)


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY tenant_isolation_{table} ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"DROP INDEX idx_{table}_tenant_id")
        op.execute(f"ALTER TABLE {table} DROP COLUMN tenant_id")
