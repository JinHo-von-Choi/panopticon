"""Durable proposal-linked offline comparison evidence."""
from alembic import op
revision = '018_proposal_validation'
down_revision = '017_asset_context'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE config_proposals ADD COLUMN validation_runs JSONB NOT NULL DEFAULT '{}'::jsonb")


def downgrade():
    op.execute('ALTER TABLE config_proposals DROP COLUMN validation_runs')
