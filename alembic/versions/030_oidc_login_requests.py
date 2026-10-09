"""브라우저에 묶인 일회용 OIDC 로그인 요청."""
from alembic import op

revision = '030_oidc_login_requests'
down_revision = '029_oidc_identities'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
CREATE TABLE oidc_login_requests (
    state_hash VARCHAR(64) PRIMARY KEY,
    browser_hash VARCHAR(64) NOT NULL,
    protected TEXT NOT NULL CHECK(length(protected) <= 4096),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_oidc_login_expiry ON oidc_login_requests(expires_at);
""")


def downgrade():
    op.execute('DROP TABLE oidc_login_requests')
