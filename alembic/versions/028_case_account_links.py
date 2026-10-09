"""사건 담당자와 인계 작성자의 개인 계정 연결."""
from alembic import op

revision = '028_case_account_links'
down_revision = '027_user_accounts'
branch_labels = None
depends_on = None


def upgrade():
    for table in ('case_workflows', 'case_history'):
        op.execute(f'ALTER TABLE {table} ADD COLUMN owner_id UUID REFERENCES user_accounts(id)')
        op.execute(f'ALTER TABLE {table} ADD COLUMN actor_id UUID REFERENCES user_accounts(id)')
    op.execute('CREATE INDEX case_workflows_owner_id_idx ON case_workflows(owner_id)')


def downgrade():
    op.execute('DROP INDEX IF EXISTS case_workflows_owner_id_idx')
    for table in ('case_history', 'case_workflows'):
        op.execute(f'ALTER TABLE {table} DROP COLUMN actor_id')
        op.execute(f'ALTER TABLE {table} DROP COLUMN owner_id')
