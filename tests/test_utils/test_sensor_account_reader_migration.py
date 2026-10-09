"""실제 마이그레이션으로 계정 보존·함수 권한과 복원을 확인한다."""

from contextlib import closing
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import psycopg2
from psycopg2 import sql


def test_account_reader_upgrade_downgrade_preserves_accounts(config,tmp_path):
    pg=config.section('postgresql');schema='account_reader_'+uuid4().hex
    env=os.environ.copy();env.update({'NETWATCHER_SKIP_DOTENV':'1','NETWATCHER_DB_HOST':str(pg['host']),
        'NETWATCHER_DB_PORT':str(pg['port']),'NETWATCHER_DB_NAME':pg['database'],
        'NETWATCHER_DB_USER':pg['username'],'NETWATCHER_DB_PASSWORD':pg['password'],
        'NETWATCHER_DB_SEARCH_PATH':schema+',public'})
    root=Path(__file__).resolve().parents[2]
    with closing(psycopg2.connect(host=pg['host'],port=pg['port'],dbname=pg['database'],
            user=pg['username'],password=pg['password'],connect_timeout=5)) as conn:
        conn.autocommit=True
        with conn.cursor() as cursor:
            cursor.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
            cursor.execute(sql.SQL('SET search_path TO {},public').format(sql.Identifier(schema)))
            def migrate(operation,revision):
                result=subprocess.run([sys.executable,'-m','alembic',operation,revision],cwd=root,env=env,
                    capture_output=True,text=True,timeout=90)
                path=tmp_path/(operation+'-'+revision+'.log');path.write_text(result.stdout+result.stderr);path.chmod(0o600)
                assert result.returncode==0,'Inspect owned migration log'
            def account():
                cursor.execute('SELECT row_to_json(a) FROM user_accounts a WHERE username=\'reader-test\'')
                return cursor.fetchone()[0]
            try:
                migrate('upgrade','035_proposal_sensor_origin')
                identifier=str(uuid4())
                cursor.execute("INSERT INTO user_accounts(id,username,password_hash,role,changed_by) VALUES(%s,'reader-test','test-hash','admin','test')",(identifier,))
                original=account()
                migrate('upgrade','036_sensor_account_reader')
                assert account()==original
                cursor.execute('SELECT * FROM sensor_account_for_share(%s)',(identifier,))
                assert cursor.fetchone()==('admin',True,1)
                cursor.execute("SELECT prosecdef,proconfig,NOT EXISTS(SELECT 1 FROM aclexplode(proacl) WHERE grantee=0 AND privilege_type='EXECUTE') FROM pg_proc WHERE oid=to_regprocedure('sensor_account_for_share(uuid)')")
                secure,settings,private=cursor.fetchone()
                assert secure and private and settings==['search_path=pg_catalog, pg_temp']
                migrate('downgrade','035_proposal_sensor_origin')
                assert account()==original
                cursor.execute("SELECT to_regprocedure('sensor_account_for_share(uuid)')")
                assert cursor.fetchone()[0] is None
                migrate('upgrade','036_sensor_account_reader')
                assert account()==original
            finally:
                cursor.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
