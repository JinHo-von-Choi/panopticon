"""EVE 입력별 보존 용량 집계."""
from alembic import op

revision = "021_eve_storage_budget"
down_revision = "020_eve_ingestion"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE eve_records ADD COLUMN accounted_bytes BIGINT NOT NULL DEFAULT 0;
        UPDATE eve_records SET accounted_bytes=octet_length(record::text)*
            CASE WHEN event_id IS NULL THEN 1 ELSE 2 END+1024;
        CREATE TABLE eve_storage_usage (
            sensor_id VARCHAR(64) NOT NULL, source_id VARCHAR(64) NOT NULL,
            record_count BIGINT NOT NULL DEFAULT 0 CHECK(record_count >= 0),
            accounted_bytes BIGINT NOT NULL DEFAULT 0 CHECK(accounted_bytes >= 0),
            PRIMARY KEY(sensor_id, source_id)
        );
        INSERT INTO eve_storage_usage(sensor_id,source_id,record_count,accounted_bytes)
            SELECT sensor_id,source_id,count(*),sum(accounted_bytes) FROM eve_records GROUP BY sensor_id,source_id;
        CREATE INDEX idx_eve_records_source_received ON eve_records(sensor_id,source_id,received_at);
    """)


def downgrade():
    op.execute("DROP INDEX idx_eve_records_source_received")
    op.execute("DROP TABLE eve_storage_usage")
    op.execute("ALTER TABLE eve_records DROP COLUMN accounted_bytes")
