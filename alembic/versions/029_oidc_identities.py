"""관리자가 지정한 OIDC 발급자·사용자와 개인 계정의 연결."""
from alembic import op

revision = '029_oidc_identities'
down_revision = '028_case_account_links'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
CREATE TABLE oidc_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    issuer VARCHAR(512) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    UNIQUE(issuer,subject),
    UNIQUE(user_id,issuer)
);
""")


def downgrade():
    op.execute('DROP TABLE oidc_identities')
