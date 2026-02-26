"""events 테이블에 reasoning TEXT 컬럼 추가

Revision ID: 003_events_reasoning
Revises: 002_asset_inventory
Create Date: 2026-02-27
"""
from typing import Sequence, Union

from alembic import op

revision: str = "003_events_reasoning"
down_revision: Union[str, None] = "002_asset_inventory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE events
            ADD COLUMN IF NOT EXISTS reasoning TEXT
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE events
            DROP COLUMN IF EXISTS reasoning
    """)
