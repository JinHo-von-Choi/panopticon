"""events 테이블에 MITRE ATT&CK ID 컬럼 추가

Revision ID: 005_events_mitre_attack
Revises: 004_events_i18n_keys
Create Date: 2026-03-05
"""
from typing import Sequence, Union

from alembic import op

revision: str = "005_events_mitre_attack"
down_revision: Union[str, None] = "004_events_i18n_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE events
            ADD COLUMN IF NOT EXISTS mitre_attack_id VARCHAR(64)
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_mitre
        ON events(mitre_attack_id)
        WHERE mitre_attack_id IS NOT NULL
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_events_mitre")
    op.execute("ALTER TABLE events DROP COLUMN IF EXISTS mitre_attack_id")
