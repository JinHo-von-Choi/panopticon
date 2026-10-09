"""독립 실행기의 승인 연결과 영속 실행 의도."""

from alembic import op

revision = "031_execution_claims"
down_revision = "030_oidc_login_requests"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE response_execution_bindings (
            action_id BIGINT PRIMARY KEY REFERENCES response_actions(id),
            actor_id UUID NOT NULL REFERENCES user_accounts(id),
            actor_version BIGINT NOT NULL CHECK(actor_version > 0),
            device_id BIGINT NOT NULL REFERENCES devices(id),
            mapping_version BIGINT NOT NULL CHECK(mapping_version >= 0),
            scope JSONB NOT NULL,
            reason VARCHAR(512) NOT NULL CHECK(length(reason) > 0),
            approval_expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("""
        CREATE TABLE response_execution_claims (
            action_id BIGINT NOT NULL REFERENCES response_actions(id),
            operation VARCHAR(8) NOT NULL CHECK(operation IN ('apply','remove')),
            request_hash VARCHAR(64) NOT NULL,
            status VARCHAR(16) NOT NULL CHECK(status IN ('prepared','completed')),
            result JSONB,
            prepared_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            completed_at TIMESTAMPTZ,
            PRIMARY KEY(action_id, operation),
            CHECK((status = 'prepared' AND result IS NULL AND completed_at IS NULL)
               OR (status = 'completed' AND result IS NOT NULL AND completed_at IS NOT NULL))
        )
    """)
    op.execute("CREATE INDEX idx_execution_claims_prepared ON response_execution_claims(prepared_at)")


def downgrade():
    op.execute("DROP TABLE response_execution_claims")
    op.execute("DROP TABLE response_execution_bindings")
