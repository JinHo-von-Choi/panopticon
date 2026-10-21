"""분석 경험 라이브러리."""

from alembic import op

from netwatcher.storage.schemas import (
    ANALYSIS_EXPERIENCES_INDEXES,
    ANALYSIS_EXPERIENCES_TABLE,
)

revision = "043_analysis_experiences"
down_revision = "042_proposal_probe"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(ANALYSIS_EXPERIENCES_TABLE)
    for statement in ANALYSIS_EXPERIENCES_INDEXES:
        op.execute(statement)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS analysis_experiences")
