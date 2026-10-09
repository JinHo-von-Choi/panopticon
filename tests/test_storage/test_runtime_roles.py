"""실제 역할·함수·테이블 권한으로 런타임의 관리 권한과 비밀 접근을 거절한다."""

from contextlib import closing
import secrets
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

from netwatcher.storage.account_access import ACCOUNT_LOCK_FUNCTION_SQL
from netwatcher.storage.runtime_roles import provision_roles,grant_runtime
from netwatcher.storage.schemas import ALL_SCHEMAS


def test_real_runtime_roles_have_separate_credentials_and_deny_ddl_hash_and_audit_changes(config):
    pg=config.section('postgresql');prefix='role_'+uuid4().hex[:12];schema=prefix
    names={kind:prefix+'_'+kind for kind in ('migrate','console','sensor')}
    passwords={kind:secrets.token_hex(32) for kind in names}
    lease_owner, retired_id = str(uuid4()), str(uuid4())
    options=dict(host=pg['host'],port=pg['port'],dbname=pg['database'])
    with closing(psycopg2.connect(**options,user=pg['username'],password=pg['password'])) as admin:
        admin.autocommit=True
        try:
            with admin:provision_roles(admin,names,schema,'Panopticon test',passwords)
            with closing(psycopg2.connect(**options,user=names['migrate'],password=passwords['migrate'])) as migrate:
                with migrate.cursor() as cur:
                    cur.execute(sql.SQL('SET search_path TO {},public').format(sql.Identifier(schema)))
                    for statement in ALL_SCHEMAS:cur.execute(statement)
                    cur.execute('CREATE TABLE alembic_version(version_num varchar(32) PRIMARY KEY)')
                    cur.execute("INSERT INTO user_accounts(id,username,password_hash,role,changed_by) VALUES(%s,'test','test-hash','admin','test')",(str(uuid4()),))
                with migrate.cursor() as cur:
                    cur.execute("INSERT INTO sensor_runtime_state(sensor_id,owner,lease_expires_at) VALUES('roles-test',%s,clock_timestamp()+INTERVAL '1 hour')",(lease_owner,))
                    cur.execute('''INSERT INTO sensor_control_claims(request_id,sensor_id,owner,actor_id,command_hash,status,result,completed_at)
                        VALUES(%s,'roles-test',%s,%s,%s,'completed','{"status":"applied"}',clock_timestamp())''',
                        (retired_id,lease_owner,str(uuid4()),'a'*64))
                grant_runtime(migrate,names,schema)
                migrate.commit()
            for kind in ('console','sensor'):
                with closing(psycopg2.connect(**options,user=names[kind],password=passwords[kind])) as runtime:
                    runtime.autocommit=True
                    with runtime.cursor() as cur:
                        cur.execute(sql.SQL('SET search_path TO {},public').format(sql.Identifier(schema)))
                        cur.execute('SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user')
                        assert not any(cur.fetchone())
                        for query in ('CREATE TABLE forbidden(id int)','UPDATE audit_log SET action=\'forged\'','DELETE FROM audit_log'):
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute(query)
                        cur.execute("INSERT INTO audit_log(user_id,action,resource) VALUES('test','read','test')")
                        cur.execute("SELECT has_function_privilege(current_user,'archive_sensor_claims(text,uuid,uuid,integer)','EXECUTE')")
                        assert cur.fetchone()[0] == (kind=='sensor')
                        if kind=='sensor':
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute('SELECT password_hash FROM user_accounts')
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute('DELETE FROM business_reviews')
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute('DELETE FROM sensor_control_claims')
                            cur.execute('SELECT * FROM sensor_account_for_share(%s)',(str(uuid4()),));assert cur.fetchone() is None
                            cur.execute('SELECT archive_sensor_claims(%s,%s,%s,1)',('roles-test',lease_owner,str(uuid4())))
                            assert cur.fetchone()[0] is False
                            cur.execute('SELECT count(*) FROM sensor_control_claims');assert cur.fetchone()[0]==0
                            cur.execute('SELECT archive_sensor_claims(%s,%s,%s,1)',('roles-test',lease_owner,retired_id))
                            assert cur.fetchone()[0] is True
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute('SELECT * FROM audit_log')

                        else:
                            cur.execute('SELECT password_hash FROM user_accounts');assert cur.fetchone()[0]=='test-hash'
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute('UPDATE sensor_runtime_state SET stopped=true')
                            with pytest.raises(psycopg2.errors.InsufficientPrivilege):cur.execute('UPDATE sensor_control_claims SET status=\'completed\'')
            with admin:provision_roles(admin,names,schema,'Panopticon test',passwords)
        finally:
            with admin.cursor() as cur:
                cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
                for name in names.values():
                    cur.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)',(name,))
                    if not cur.fetchone()[0]:continue
                    cur.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(name)))
                    cur.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(name)))
