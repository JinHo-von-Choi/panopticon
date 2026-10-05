"""response_actions.mapping_confirmed_at 추가 (계획서 4장, PR 14).

Revision ID: 014_action_mapping_freshness
Revises: 013_response_proposals
Create Date: 2026-10-06

    "응답 지연 시 캐시된 매핑으로 실행하지 않는다."

제안 단계에서는 오래된 매핑을 불확실성으로 남기되, **실행 시점** 에는
막아야 한다. 그래서 승인 순간의 매핑 확인 시각을 조치 레코드에 고정한다.
그대로 없으면 실행 시점에 "언제 확인했는지" 알 수 없어 규칙을 적용할 수 없다.
"""

from __future__ import annotations

from alembic import op

revision = "014_action_mapping_freshness"
down_revision = "013_response_proposals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE response_actions "
        "ADD COLUMN IF NOT EXISTS mapping_confirmed_at TIMESTAMPTZ"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE response_actions DROP COLUMN IF EXISTS mapping_confirmed_at"
    )
