"""프로세스가 분리된 센서의 실행 소유권과 관측 상태."""

from alembic import op

revision = "032_sensor_runtime_state"
down_revision = "031_execution_claims"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE sensor_runtime_state (
            sensor_id VARCHAR(128) PRIMARY KEY,
            owner UUID NOT NULL,
            started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
            lease_expires_at TIMESTAMPTZ NOT NULL,
            stopped BOOLEAN NOT NULL DEFAULT FALSE,
            snapshot JSONB NOT NULL DEFAULT '{}',
            CHECK(length(sensor_id) > 0),
            CHECK(jsonb_typeof(snapshot) = 'object'),
            CHECK(octet_length(snapshot::text) <= 65536)
        )
    """)


def downgrade():
    op.execute("DROP TABLE sensor_runtime_state")
