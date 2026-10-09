"""센서 변경 기록의 감사 보관과 제한된 정리."""

from alembic import op
from netwatcher.storage.sensor_claim_retention import SENSOR_CLAIM_RETENTION_SQL

revision = '037_sensor_claim_retention'
down_revision = '036_sensor_account_reader'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(SENSOR_CLAIM_RETENTION_SQL)


def downgrade():
    # 보관된 감사 기록은 삭제하거나 원래 예약으로 되돌리지 않는다.
    op.execute('DROP FUNCTION archive_sensor_claims(text,uuid,uuid,integer)')
    op.execute('DROP INDEX idx_audit_sensor_archived_request')
    op.execute('DROP INDEX idx_sensor_claim_retention')
    op.execute('DROP INDEX idx_audit_sensor_request_lookup')
