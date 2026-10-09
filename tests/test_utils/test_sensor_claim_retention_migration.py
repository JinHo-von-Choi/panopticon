"""실제 이전 스키마의 업데이트·되돌리기·재업데이트에서 감사 기록과 ACL을 보존한다."""

from contextlib import closing
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import psycopg2
from psycopg2 import sql


def test_claim_retention_migration_preserves_archived_audit_and_reinstalls_private_function(config,tmp_path):
    pg=config.section('postgresql');schema='retention_'+uuid4().hex
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
            try:
                migrate('upgrade','036_sensor_account_reader')
                owner,request,actor=map(str,(uuid4(),uuid4(),uuid4()))
                cursor.execute("INSERT INTO sensor_runtime_state(sensor_id,owner,lease_expires_at) VALUES('test',%s,clock_timestamp()+INTERVAL '1 hour')",(owner,))
                cursor.execute("""INSERT INTO sensor_control_claims(request_id,sensor_id,owner,actor_id,command_hash,status,result,completed_at)
                    VALUES(%s,'test',%s,%s,%s,'completed','{"status":"applied"}',clock_timestamp())""",(request,owner,actor,'a'*64))
                migrate('upgrade','037_sensor_claim_retention')
                cursor.execute("SELECT count(*) FROM sensor_control_claims");assert cursor.fetchone()[0]==1
                cursor.execute('SELECT archive_sensor_claims(%s,%s,%s,1)',('test',owner,str(uuid4())))
                assert cursor.fetchone()[0] is False
                cursor.execute('SELECT count(*) FROM sensor_control_claims');assert cursor.fetchone()[0]==0
                cursor.execute("SELECT details FROM audit_log WHERE action='sensor_change_archived'")
                archived=cursor.fetchone()[0];assert archived['request_id']==request and archived['outcome']=='applied'
                cursor.execute("SELECT prosecdef,proconfig,NOT EXISTS(SELECT 1 FROM aclexplode(proacl) WHERE grantee=0 AND privilege_type='EXECUTE') FROM pg_proc WHERE oid=to_regprocedure('archive_sensor_claims(text,uuid,uuid,integer)')")
                secure,settings,private=cursor.fetchone();assert secure and private and settings==['search_path=pg_catalog, pg_temp']
                migrate('downgrade','036_sensor_account_reader')
                cursor.execute("SELECT details FROM audit_log WHERE action='sensor_change_archived'");assert cursor.fetchone()[0]==archived
                migrate('upgrade','037_sensor_claim_retention')
                cursor.execute('SELECT archive_sensor_claims(%s,%s,%s,1)',('test',owner,request));assert cursor.fetchone()[0] is True
                cursor.execute('SELECT count(*) FROM sensor_control_claims');assert cursor.fetchone()[0]==0
            finally:
                cursor.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
