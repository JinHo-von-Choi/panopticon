"""events 테이블에 i18n 번역 키 컬럼 추가

Revision ID: 004_events_i18n_keys
Revises: 003_events_reasoning
Create Date: 2026-03-01
"""
from typing import Sequence, Union

from alembic import op

revision: str = "004_events_i18n_keys"
down_revision: Union[str, None] = "003_events_reasoning"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE events
            ADD COLUMN IF NOT EXISTS title_key TEXT,
            ADD COLUMN IF NOT EXISTS description_key TEXT
    """)


def downgrade() -> None:
    op.execute("""
        ALTER TABLE events
            DROP COLUMN IF EXISTS title_key,
            DROP COLUMN IF EXISTS description_key
    """)
