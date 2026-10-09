"""센서 설정 변경의 영속 중복 실행 방지."""

from alembic import op

revision = "034_sensor_control_claims"
down_revision = "033_event_stream_notifications"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""CREATE TABLE sensor_control_claims (
        request_id UUID PRIMARY KEY,
        sensor_id VARCHAR(128) NOT NULL,
        owner UUID NOT NULL,
        actor_id UUID NOT NULL,
        command_hash VARCHAR(64) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'prepared' CHECK(status IN ('prepared','completed')),
        result JSONB,
        prepared_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        completed_at TIMESTAMPTZ,
        CHECK((status='prepared' AND result IS NULL AND completed_at IS NULL)
           OR (status='completed' AND result IS NOT NULL AND completed_at IS NOT NULL)),
        CHECK(result IS NULL OR (jsonb_typeof(result)='object' AND octet_length(result::text)<=65536))
    )""")


def downgrade():
    op.execute("DROP TABLE sensor_control_claims")
