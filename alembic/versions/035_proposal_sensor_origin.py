"""설정 제안을 원래 센서와 실행 세대·설정 버전에 연결한다."""

from alembic import op

revision = "035_proposal_sensor_origin"
down_revision = "034_sensor_control_claims"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""ALTER TABLE config_proposals
        ADD COLUMN sensor_id VARCHAR(128),
        ADD COLUMN sensor_owner UUID,
        ADD COLUMN source_version VARCHAR(64),
        ADD CONSTRAINT config_proposals_origin_check CHECK (
          (sensor_id IS NULL AND sensor_owner IS NULL AND source_version IS NULL)
          OR (sensor_id IS NOT NULL AND length(sensor_id)>0 AND sensor_owner IS NOT NULL
              AND source_version IS NOT NULL AND source_version ~ '^[a-f0-9]{64}$'))""")
    op.execute("CREATE INDEX idx_config_proposals_sensor ON config_proposals(sensor_id,created_at DESC,id DESC)")


def downgrade():
    op.execute("DROP INDEX idx_config_proposals_sensor")
    op.execute("""ALTER TABLE config_proposals DROP CONSTRAINT config_proposals_origin_check,
        DROP COLUMN sensor_id, DROP COLUMN sensor_owner, DROP COLUMN source_version""")
