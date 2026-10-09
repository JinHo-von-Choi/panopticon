"""센서의 계정 확인에 비밀번호 조회나 계정 수정 권한을 요구하지 않는다."""

from alembic import op
from netwatcher.storage.account_access import ACCOUNT_LOCK_FUNCTION_SQL

revision = '036_sensor_account_reader'
down_revision = '035_proposal_sensor_origin'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(ACCOUNT_LOCK_FUNCTION_SQL)


def downgrade():
    op.execute('DROP FUNCTION sensor_account_for_share(uuid)')
