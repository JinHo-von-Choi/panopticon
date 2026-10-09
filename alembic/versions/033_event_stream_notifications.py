"""커밋된 경보의 키를 분리 콘솔에 전달한다."""

from alembic import op

revision = "033_event_stream_notifications"
down_revision = "032_sensor_runtime_state"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE FUNCTION notify_committed_event() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            PERFORM pg_catalog.pg_notify('nw_events_' || pg_catalog.md5(TG_TABLE_SCHEMA),
                pg_catalog.json_build_object('id',NEW.id,'timestamp',NEW.timestamp)::text);
            RETURN NEW;
        END;
        $$
    """)
    op.execute("CREATE TRIGGER events_stream_notify AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION notify_committed_event()")


def downgrade():
    op.execute("DROP TRIGGER events_stream_notify ON events")
    op.execute("DROP FUNCTION notify_committed_event()")
