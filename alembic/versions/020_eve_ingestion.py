"""EVE 원본 참조와 수집 체크포인트."""
from alembic import op

revision = "020_eve_ingestion"
down_revision = "019_audit_request_index"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE eve_checkpoints (
            sensor_id VARCHAR(64) NOT NULL, source_id VARCHAR(64) NOT NULL,
            revision BIGINT NOT NULL DEFAULT 0, state JSONB NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY(sensor_id, source_id)
        );
        CREATE TABLE eve_records (
            ingest_id UUID PRIMARY KEY, sensor_id VARCHAR(64) NOT NULL,
            source_id VARCHAR(64) NOT NULL, event_type VARCHAR(64) NOT NULL,
            observed_at TIMESTAMPTZ, received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            record JSONB NOT NULL, event_id BIGINT
        );
        CREATE INDEX idx_eve_records_flow ON eve_records(sensor_id, source_id, (record->>'flow_id'));
        CREATE INDEX idx_eve_records_received ON eve_records(received_at);
    """)


def downgrade():
    op.execute("DROP TABLE eve_records")
    op.execute("DROP TABLE eve_checkpoints")
