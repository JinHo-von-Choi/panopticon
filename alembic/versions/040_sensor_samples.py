"""센서 운영 표본."""

from alembic import op

from netwatcher.storage.schemas import SENSOR_SAMPLES_TABLE

revision = "040_sensor_samples"
down_revision = "039_audit_log_hash_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(SENSOR_SAMPLES_TABLE)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS sensor_samples")
