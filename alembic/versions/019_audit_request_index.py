"""요청 ID로 변경 감사 기록을 조회하는 인덱스."""
from alembic import op

revision = "019_audit_request_index"
down_revision = "018_proposal_validation"
branch_labels = None
depends_on = None


def upgrade():
    # 이전 JSONB 문자열을 객체로 복원한다. 잘못된 외부 기록은 삭제하지 않는다.
    op.execute("""
        DO $$ DECLARE entry RECORD; BEGIN
          FOR entry IN SELECT id, details #>> '{}' AS encoded FROM audit_log
                       WHERE jsonb_typeof(details)='string' LOOP
            BEGIN
              UPDATE audit_log SET details=entry.encoded::jsonb WHERE id=entry.id;
            EXCEPTION WHEN invalid_text_representation THEN
              NULL;
            END;
          END LOOP;
        END $$;
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_request ON audit_log((details->>'request_id'), created_at, id)")


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_audit_log_request")
