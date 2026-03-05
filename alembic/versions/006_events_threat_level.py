"""events 테이블에 threat_level 컬럼 추가

Revision ID: 006_events_threat_level
Revises: 005_events_mitre_attack
Create Date: 2026-03-05
"""
from typing import Sequence, Union

from alembic import op

revision: str = "006_events_threat_level"
down_revision: Union[str, None] = "005_events_mitre_attack"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE events
            ADD COLUMN IF NOT EXISTS threat_level SMALLINT NOT NULL DEFAULT 0
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE events DROP COLUMN IF EXISTS threat_level")
