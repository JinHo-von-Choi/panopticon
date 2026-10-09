"""반복 EVE 경보 조회 인덱스."""
from alembic import op
revision = '026_event_group_indexes'
down_revision = '025_work_schedules'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE INDEX IF NOT EXISTS idx_eve_records_event ON eve_records(event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_eve_records_alert_window ON eve_records(sensor_id,source_id,observed_at)
    WHERE event_type='alert';""")


def downgrade():
    op.execute('DROP INDEX IF EXISTS idx_eve_records_alert_window')
    op.execute('DROP INDEX IF EXISTS idx_eve_records_event')
