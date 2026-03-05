"""devices 테이블에 host_labels 컬럼 추가.

Revision ID: 007_devices_host_labels
Revises: 006_events_threat_level
Create Date: 2026-03-05
"""

from __future__ import annotations

from alembic import op

revision = "007_devices_host_labels"
down_revision = "006_events_threat_level"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS host_labels JSONB NOT NULL DEFAULT '[]'"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_host_labels "
        "ON devices USING gin(host_labels) WHERE host_labels != '[]'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_devices_host_labels")
    op.execute("ALTER TABLE devices DROP COLUMN IF EXISTS host_labels")
