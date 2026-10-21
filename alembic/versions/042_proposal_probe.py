"""설정 제안 대비 결과."""

from alembic import op

from netwatcher.storage.schemas import CONFIG_PROPOSALS_PROBE_DEFAULT

import json

revision = "042_proposal_probe"
down_revision = "041_observed_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    default = json.dumps(CONFIG_PROPOSALS_PROBE_DEFAULT)
    op.execute(
        "ALTER TABLE config_proposals ADD COLUMN IF NOT EXISTS probe JSONB "
        f"NOT NULL DEFAULT '{default}'::jsonb"
    )
    op.execute(
        "ALTER TABLE config_proposals DROP CONSTRAINT IF EXISTS config_proposals_probe_check"
    )
    op.execute(
        "ALTER TABLE config_proposals ADD CONSTRAINT config_proposals_probe_check "
        "CHECK (probe ? 'status')"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE config_proposals DROP CONSTRAINT IF EXISTS config_proposals_probe_check"
    )
    op.execute("ALTER TABLE config_proposals DROP COLUMN IF EXISTS probe")
