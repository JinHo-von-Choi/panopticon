"""신규 분리 설치의 DB 역할을 만들고 명시한 테이블 권한만 부여한다."""

import argparse
import os
import re

import psycopg2
from psycopg2 import sql

SENSOR_READ = {'alembic_version','events','devices','custom_blocklist','traffic_stats','incidents','config_proposals',
    'evidence_records','replay_traces','replay_runs','replay_results','event_ingest','flush_receipts',
    'asset_context_history','work_schedules','event_work_links','sensor_runtime_state','sensor_control_claims'}
SENSOR_WRITE = {'events','devices','custom_blocklist','traffic_stats','incidents','config_proposals',
    'evidence_records','event_ingest','flush_receipts','asset_context_history','sensor_runtime_state','sensor_control_claims'}
CONSOLE_READ = SENSOR_READ | {'audit_log','business_reviews','case_workflows','case_history',
    'business_review_history','user_accounts','oidc_identities','oidc_login_requests',
    'response_actions','response_receipts','response_proposals','response_execution_bindings','response_execution_claims'}
CONSOLE_WRITE = {'events','devices','incidents','replay_traces','replay_runs','replay_results',
    'business_reviews','case_workflows','work_schedules',
    'event_work_links','user_accounts','oidc_identities','oidc_login_requests'}
CONSOLE_DELETE = {'events','event_ingest','traffic_stats','flush_receipts','incidents',
    'business_reviews','case_workflows','event_work_links','work_schedules','oidc_login_requests',
    'replay_traces','replay_runs','replay_results'}


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,62}',value):
        raise ValueError('DB 역할 또는 스키마 이름을 확인하세요')
    return value


def settings():
    names={kind:identifier(os.environ['PANOPTICON_DB_'+kind.upper()+'_ROLE']) for kind in ('migrate','console','sensor')}
    if len(set(names.values()))!=3:raise ValueError('DB 역할은 서로 달라야 합니다')
    schema=identifier(os.environ.get('NETWATCHER_DB_SEARCH_PATH','netwatcher,public').split(',')[0])
    installation=os.environ['PANOPTICON_DB_INSTALLATION']
    if not re.fullmatch(r'[a-z0-9-]{1,64}',installation):raise ValueError('설치 식별자를 확인하세요')
    return names,schema,'Panopticon '+installation


def provision_roles(conn,names,schema,marker,passwords):
    """타 설치의 역할·스키마를 가져오거나 권한을 낮추지 않는다."""
    with conn.cursor() as cur:
        for kind,name in names.items():
            password=passwords[kind]
            if not isinstance(password,str) or not re.fullmatch(r'[a-f0-9]{64}',password):
                raise ValueError('DB 자격증명을 확인하세요')
            cur.execute("SELECT oid,shobj_description(oid,'pg_authid'),rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",(name,))
            existing=cur.fetchone()
            if existing and existing[1]!=marker:raise ValueError('다른 설치의 DB 역할이 이미 있습니다')
            if existing and any(existing[2:]):raise ValueError('DB 역할에 예상 밖의 관리 권한이 있습니다')
            if existing:
                cur.execute('SELECT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=%s)',(existing[0],))
                if cur.fetchone()[0]:raise ValueError('DB 역할에 예상 밖의 역할 상속이 있습니다')
            if not existing:
                cur.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS').format(sql.Identifier(name)))
                cur.execute(sql.SQL('COMMENT ON ROLE {} IS %s').format(sql.Identifier(name)),(marker,))
            cur.execute(sql.SQL('ALTER ROLE {} PASSWORD %s').format(sql.Identifier(name)),(password,))
            cur.execute(sql.SQL("ALTER ROLE {} SET idle_in_transaction_session_timeout='15s'").format(sql.Identifier(name)))
        cur.execute('SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname=%s',(schema,))
        existing=cur.fetchone()
        if existing and existing[0]!=names['migrate']:raise ValueError('기존 스키마의 소유자를 변경하지 않습니다')
        cur.execute(sql.SQL('CREATE SCHEMA IF NOT EXISTS {} AUTHORIZATION {}').format(sql.Identifier(schema),sql.Identifier(names['migrate'])))
        cur.execute('SELECT current_database()');database=cur.fetchone()[0]
        cur.execute(sql.SQL('GRANT CONNECT,CREATE ON DATABASE {} TO {}').format(sql.Identifier(database),sql.Identifier(names['migrate'])))


def grant_runtime(conn,names,schema):
    """감사 수정·DDL·다른 역할의 자격증명 접근을 런타임에 허용하지 않는다."""
    with conn.cursor() as cur:
        for kind,reads,writes,deletes in (
            ('sensor',SENSOR_READ,SENSOR_WRITE,{'custom_blocklist'}),
            ('console',CONSOLE_READ,CONSOLE_WRITE,CONSOLE_DELETE)):
            role=sql.Identifier(names[kind])
            cur.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema),role))
            cur.execute(sql.SQL('REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM {}').format(sql.Identifier(schema),role))
            cur.execute(sql.SQL('REVOKE ALL ON ALL SEQUENCES IN SCHEMA {} FROM {}').format(sql.Identifier(schema),role))
            for privilege,tables in (('SELECT',reads),('INSERT,UPDATE',writes),('DELETE',deletes),('INSERT',{'audit_log'} | ({'case_history','business_review_history'} if kind=='console' else set()))):
                for table in sorted(tables):
                    cur.execute(sql.SQL('GRANT '+privilege+' ON {}.{} TO {}').format(sql.Identifier(schema),sql.Identifier(table),role))
            for table in sorted(writes | {'audit_log'} | ({'case_history','business_review_history'} if kind=='console' else set())):
                cur.execute('SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=%s AND table_name=%s AND column_name=\'id\')',(schema,table))
                if not cur.fetchone()[0]:continue
                # 열 기본값이 실제로 쓰는 시퀀스와 소유 시퀀스를 모두 찾는다.
                # 파티션 전환 등으로 시퀀스가 둘이 되면 소유 시퀀스만으로는 기본값 시퀀스를 놓친다.
                cur.execute("""SELECT DISTINCT s.relname FROM pg_attrdef ad
                    JOIN pg_depend d ON d.classid='pg_attrdef'::regclass AND d.objid=ad.oid
                        AND d.refclassid='pg_class'::regclass
                    JOIN pg_class s ON s.oid=d.refobjid AND s.relkind='S'
                    WHERE ad.adrelid=%s::regclass AND s.relnamespace=%s::regnamespace""",(schema+'.'+table,schema))
                defaults={row[0] for row in cur.fetchall()}
                cur.execute('SELECT pg_get_serial_sequence(%s,\'id\')',(schema+'.'+table,))
                owned=cur.fetchone()[0]
                if owned:defaults.add(owned.split('.')[-1])
                for sequence in sorted(defaults):
                    cur.execute(sql.SQL('GRANT USAGE ON SEQUENCE {}.{} TO {}').format(sql.Identifier(schema),sql.Identifier(sequence),role))
        cur.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.sensor_account_for_share(uuid) TO {}').format(sql.Identifier(schema),sql.Identifier(names['sensor'])))
        cur.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.archive_sensor_claims(text,uuid,uuid,integer) TO {}').format(sql.Identifier(schema),sql.Identifier(names['sensor'])))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('operation',choices=('roles','grants'));args=parser.parse_args()
    names,schema,marker=settings()
    with psycopg2.connect(host=os.environ['NETWATCHER_DB_HOST'],port=os.environ.get('NETWATCHER_DB_PORT','5432'),
        dbname=os.environ['NETWATCHER_DB_NAME'],user=os.environ['NETWATCHER_DB_USER'],
        password=os.environ['NETWATCHER_DB_PASSWORD'],connect_timeout=10) as conn:
        if args.operation=='roles':
            provision_roles(conn,names,schema,marker,{kind:os.environ['PANOPTICON_DB_'+kind.upper()+'_PASSWORD'] for kind in names})
        else:grant_runtime(conn,names,schema)


if __name__=='__main__':
    main()
