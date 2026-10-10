"""Suricata가 관측한 내부 주소."""

from alembic import op

from netwatcher.storage.schemas import OBSERVED_ASSETS_SCHEMA

revision = "041_observed_assets"
down_revision = "040_sensor_samples"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(OBSERVED_ASSETS_SCHEMA)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS observed_asset_backfills")
    op.execute("DROP TABLE IF EXISTS observed_assets")
