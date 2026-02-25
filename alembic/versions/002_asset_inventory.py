"""asset inventory: devices 테이블에 device_type, hostname_sources, ip_history 추가

Revision ID: 002_asset_inventory
Revises: 001_baseline
Create Date: 2026-02-25
"""
from typing import Sequence, Union

from alembic import op

revision: str = "002_asset_inventory"
down_revision: Union[str, None] = "001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE devices
            ADD COLUMN IF NOT EXISTS device_type      VARCHAR(32) NOT NULL DEFAULT 'unknown',
            ADD COLUMN IF NOT EXISTS hostname_sources JSONB       NOT NULL DEFAULT '{}',
            ADD COLUMN IF NOT EXISTS ip_history       JSONB       NOT NULL DEFAULT '[]'
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_type "
        "ON devices(device_type) WHERE device_type != 'unknown'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_devices_type")
    op.execute("""
        ALTER TABLE devices
            DROP COLUMN IF EXISTS device_type,
            DROP COLUMN IF EXISTS hostname_sources,
            DROP COLUMN IF EXISTS ip_history
    """)
