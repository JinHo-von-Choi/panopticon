"""수동 자산 역할, IP 매핑 세대와 원자적 확인 이력."""
from alembic import op
ASSET_CONTEXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_context_history (
    id BIGSERIAL PRIMARY KEY,
    mac_address MACADDR NOT NULL,
    version BIGINT NOT NULL,
    profile JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(mac_address, version)
);
CREATE OR REPLACE FUNCTION bump_device_mapping() RETURNS trigger AS $$
BEGIN
    IF NEW.ip_address IS DISTINCT FROM OLD.ip_address THEN
        NEW.ip_mapping_version := OLD.ip_mapping_version + 1;
    ELSE
        NEW.ip_mapping_version := OLD.ip_mapping_version;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS devices_mapping_generation ON devices;
CREATE TRIGGER devices_mapping_generation BEFORE UPDATE ON devices
FOR EACH ROW EXECUTE FUNCTION bump_device_mapping();
"""

revision = '017_asset_context'
down_revision = '016_event_ingest'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE devices ADD COLUMN context_profile JSONB NOT NULL DEFAULT '{}'::jsonb")
    op.execute('ALTER TABLE devices ADD COLUMN context_version BIGINT NOT NULL DEFAULT 0')
    op.execute('ALTER TABLE devices ADD COLUMN ip_mapping_version BIGINT NOT NULL DEFAULT 0')
    op.execute(ASSET_CONTEXT_SCHEMA)


def downgrade():
    op.execute('DROP TRIGGER IF EXISTS devices_mapping_generation ON devices')
    op.execute('DROP FUNCTION IF EXISTS bump_device_mapping()')
    op.execute('DROP TABLE IF EXISTS asset_context_history')
    op.execute('ALTER TABLE devices DROP COLUMN context_profile, DROP COLUMN context_version, DROP COLUMN ip_mapping_version')
