"""v0.4.0 자료의 업그레이드와 PostgreSQL 백업 복원을 실제 DB에서 검증한다."""

import bcrypt
from cryptography.fernet import Fernet

from contextlib import closing
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import uuid

from alembic.config import Config as AlembicConfig
from alembic.script import ScriptDirectory
import psycopg2
from psycopg2 import sql


ROOT = Path(__file__).resolve().parents[2]
TABLES = ("events", "devices", "evidence_records", "audit_log", "custom_blocklist")


def test_previous_release_upgrade_and_backup_restore(config, tmp_path):
    pg = config.section("postgresql")
    connection = dict(host=pg["host"], port=pg["port"], user=pg["username"],
                      password=pg["password"], connect_timeout=5)
    prefix = "upgrade_" + uuid.uuid4().hex[:12]
    databases = [prefix + suffix for suffix in ("", "_old_restore", "_new_restore")]
    env = os.environ.copy()
    env.update(NETWATCHER_SKIP_DOTENV="1", NETWATCHER_DB_HOST=str(pg["host"]),
               NETWATCHER_DB_PORT=str(pg["port"]), NETWATCHER_DB_USER=pg["username"],
               NETWATCHER_DB_PASSWORD=pg["password"], NETWATCHER_DB_SEARCH_PATH="netwatcher,public")
    # 이전 릴리스의 파일을 별도 디렉터리에 풀어 현재 구현으로 대체하지 않는다.
    archive = subprocess.run(["git", "archive", "v0.4.0"], cwd=ROOT,
                             capture_output=True, check=True).stdout
    previous = tmp_path / "previous"
    previous.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(previous, filter="data")
    log_path = tmp_path / "upgrade.log"
    log_path.touch(mode=0o600)
    created = []

    def run(command, *, cwd=ROOT, input_file=None, output_file=None):
        with log_path.open("ab") as log:
            result = subprocess.run(command, cwd=cwd, env=env, stdin=input_file,
                                    stdout=output_file or log, stderr=log, timeout=60)
        assert result.returncode == 0, f"Upgrade/restore command failed; inspect {log_path.name}"

    def migrate(source, database):
        env["NETWATCHER_DB_NAME"] = database
        run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=source)

    def client(tool, database):
        container = os.environ.get("PANOPTICON_TEST_PG_CONTAINER")
        if container:
            return ["docker", "exec", "-i", container, tool, "-U", pg["username"], "-d", database]
        env.update(PGHOST=str(pg["host"]), PGPORT=str(pg["port"]),
                   PGUSER=pg["username"], PGPASSWORD=pg["password"])
        return [tool, "-d", database]

    def dump(database, path):
        with path.open("xb") as output:
            path.chmod(0o600)
            run(client("pg_dump", database) + ["-Fc", "--no-owner", "--no-acl"], output_file=output)

    def restore(database, path):
        with path.open("rb") as input_stream:
            run(client("pg_restore", database) + ["--exit-on-error", "--single-transaction",
                                                  "--no-owner", "--no-acl"], input_file=input_stream)

    def snapshot(database):
        with closing(psycopg2.connect(dbname=database, **connection)) as conn, conn, conn.cursor() as cursor:
            cursor.execute("SET search_path TO netwatcher,public")
            result = {}
            for table in TABLES:
                cursor.execute(sql.SQL("SELECT row_to_json(t) FROM {} t ORDER BY id").format(sql.Identifier(table)))
                result[table] = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT to_regclass('netwatcher.business_reviews') IS NOT NULL")
            if cursor.fetchone()[0]:
                cursor.execute("SELECT row_to_json(t) FROM business_reviews t ORDER BY event_id")
                result["business_reviews"] = [row[0] for row in cursor.fetchall()]
            for table in ("case_workflows", "case_history", "business_review_history", "event_work_links"):
                cursor.execute("SELECT to_regclass(%s) IS NOT NULL", ("netwatcher." + table,))
                if cursor.fetchone()[0]:
                    cursor.execute(sql.SQL("SELECT row_to_json(t) FROM {} t ORDER BY event_id,version").format(sql.Identifier(table)))
                    result[table] = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT to_regclass('netwatcher.work_schedules') IS NOT NULL")
            if cursor.fetchone()[0]:
                cursor.execute("SELECT row_to_json(t) FROM work_schedules t ORDER BY id")
                result["work_schedules"] = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT to_regclass('netwatcher.user_accounts') IS NOT NULL")
            if cursor.fetchone()[0]:
                cursor.execute("SELECT row_to_json(t) FROM user_accounts t ORDER BY id")
                result["user_accounts"] = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT to_regclass('netwatcher.oidc_identities') IS NOT NULL")
            if cursor.fetchone()[0]:
                cursor.execute("SELECT row_to_json(t) FROM oidc_identities t ORDER BY id")
                result["oidc_identities"] = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT to_regclass('netwatcher.oidc_login_requests') IS NOT NULL")
            if cursor.fetchone()[0]:
                cursor.execute("SELECT row_to_json(t) FROM oidc_login_requests t ORDER BY state_hash")
                result["oidc_login_requests"] = [row[0] for row in cursor.fetchall()]
            for table, ordering in (("response_actions", "id"), ("response_receipts", "id"),
                                    ("response_execution_bindings", "action_id"),
                                    ("response_execution_claims", "action_id,operation")):
                cursor.execute("SELECT to_regclass(%s) IS NOT NULL", ("netwatcher." + table,))
                if cursor.fetchone()[0]:
                    cursor.execute(sql.SQL("SELECT row_to_json(t) FROM {} t ORDER BY " + ordering).format(sql.Identifier(table)))
                    result[table] = [row[0] for row in cursor.fetchall()]
            cursor.execute("SELECT version_num FROM alembic_version")
            result["revision"] = cursor.fetchone()[0]
            return result

    admin = psycopg2.connect(dbname=pg["database"], **connection)
    admin.autocommit = True
    try:
        with admin.cursor() as cursor:
            for database in databases:
                cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
                created.append(database)
        migrate(previous, databases[0])
        with closing(psycopg2.connect(dbname=databases[0], **connection)) as conn, conn, conn.cursor() as cursor:
            cursor.execute("SET search_path TO netwatcher,public")
            cursor.execute("""INSERT INTO events(engine,severity,title,source_ip,metadata,packet_info,resolved)
                VALUES ('port_scan','WARNING','백업 서버 연결 확인','192.0.2.10',
                        '{"evidence_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
                        '{"pcap_path":"evidence/sample.pcap"}',true)""")
            cursor.execute("""INSERT INTO devices(mac_address,ip_address,nickname,context_profile,context_version,ip_mapping_version)
                VALUES ('02:00:00:00:00:01','192.0.2.10','백업 서버',
                        '{"role":"backup","owner":"operations","expected_flows":[]}',3,2)""")
            cursor.execute("""INSERT INTO evidence_records(evidence_id,sensor_id,boot_id,engine,features,expired,missing)
                VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','test-sensor','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                        'port_scan','{"destination_count":20}',false,'[]')""")
            cursor.execute("""INSERT INTO custom_blocklist(entry_type,value,notes)
                VALUES ('ip','198.51.100.20','검토한 시험 주소')""")
            for details in ({"request_id": "c" * 32}, json.dumps({"request_id": "c" * 32}), "invalid-json"):
                cursor.execute("INSERT INTO audit_log(user_id,action,details) VALUES ('operator','authorized_intent',%s::jsonb)",
                               (json.dumps(details),))
        before = snapshot(databases[0])
        assert before["revision"] == "018_proposal_validation"
        old_backup = tmp_path / "previous.dump"
        dump(databases[0], old_backup)
        migrate(ROOT, databases[0])
        after = snapshot(databases[0])
        migration_config = AlembicConfig(str(ROOT / "alembic.ini"))
        migration_config.set_main_option("script_location", str(ROOT / "alembic"))
        assert after["revision"] == ScriptDirectory.from_config(migration_config).get_current_head()
        for table in TABLES:
            if table != "audit_log":
                expected = deepcopy(before[table])
                if table in ("events", "devices"):
                    for row in expected:
                        row["tenant_id"] = str(uuid.UUID(int=0))
                assert after[table] == expected, f"Previous records changed: {table}"
        expected_audit = deepcopy(before["audit_log"])
        for row in expected_audit:
            row["tenant_id"] = str(uuid.UUID(int=0))
            row["prev_hash"] = "0" * 64
            row["entry_hash"] = "0" * 64
        expected_audit[1]["details"] = json.loads(expected_audit[1]["details"])
        assert after["audit_log"] == expected_audit
        restore(databases[1], old_backup)
        restored_before = snapshot(databases[1])
        assert restored_before == before
        migrate(ROOT, databases[1])
        assert snapshot(databases[1]) == after
        with closing(psycopg2.connect(dbname=databases[0], **connection)) as conn, conn, conn.cursor() as cursor:
            cursor.execute("SET search_path TO netwatcher,public")
            cursor.execute("""INSERT INTO business_reviews(event_id,version,decision,note,actor,scope,reviewed_at)
                VALUES (%s,1,'investigate','인계할 조사 근거','operator','{}',NOW())""", (after["events"][0]["id"],))
            cursor.execute("""INSERT INTO case_workflows(event_id,version,owner,status,actor,updated_at)
                VALUES (%s,1,'야간 담당자','investigating','operator',NOW())""", (after["events"][0]["id"],))
            cursor.execute("""INSERT INTO case_history(event_id,version,owner,status,note,actor,updated_at)
                VALUES (%s,1,'야간 담당자','investigating','보존해야 할 인계 메모','operator',NOW())""", (after["events"][0]["id"],))
            cursor.execute("""INSERT INTO business_review_history
                SELECT event_id,version,decision,note,actor,scope,reviewed_at,expires_at FROM business_reviews""")
            cursor.execute("""INSERT INTO work_schedules(id,fingerprint,content,starts_at,ends_at,actor)
                VALUES('5d6b826b-6913-4ac8-ad96-2d69523c5e3c',repeat('a',64),
                jsonb_build_object('ticket','CHG-RESTORE','owner','backup operator','title','Verified backup',
                'kind','backup','note','Approved work reference','source_ip','192.0.2.10','source_mac',NULL,
                'dest_ip','198.51.100.20','protocol','TCP','dest_port',443,'max_flow_bytes',4096,
                'starts_at',NOW(),'ends_at',NOW()+interval '1 hour'),NOW(),NOW()+interval '1 hour','operator')""")
            cursor.execute("""INSERT INTO event_work_links(event_id,schedule_id,version,actor)
                VALUES(%s,'5d6b826b-6913-4ac8-ad96-2d69523c5e3c',1,'operator')""", (after["events"][0]["id"],))
            cursor.execute("""INSERT INTO user_accounts(id,username,password_hash,role,enabled,version,changed_by)
                VALUES('8b0280f8-6d76-4f81-b5cb-a4c0e10ee625','restore-admin',%s,'admin',TRUE,3,'setup')""",
                (bcrypt.hashpw(b'UpgradeFixturePassword-2026',bcrypt.gensalt()).decode(),))
            for table in ('case_workflows','case_history'):
                cursor.execute(sql.SQL("UPDATE {} SET owner='restore-admin',actor='restore-admin',owner_id='8b0280f8-6d76-4f81-b5cb-a4c0e10ee625',actor_id='8b0280f8-6d76-4f81-b5cb-a4c0e10ee625'").format(sql.Identifier(table)))
            cursor.execute("""INSERT INTO oidc_identities(id,user_id,issuer,subject,created_by)
                VALUES('efa03b4e-c56e-4f1b-85b0-c6934b512011',
                '8b0280f8-6d76-4f81-b5cb-a4c0e10ee625',
                'https://identity.example/restore','restore-subject','restore-admin')""")
            protected = Fernet(Fernet.generate_key()).encrypt(b'{"fixture":"encrypted-login-request"}').decode('ascii')
            cursor.execute("""INSERT INTO oidc_login_requests(state_hash,browser_hash,protected,expires_at)
                VALUES(repeat('b',64),repeat('c',64),%s,NOW()+interval '5 minutes')""", (protected,))
            cursor.execute("""INSERT INTO response_actions(target,direction,ttl_seconds,state,
                approved_hash,base_version,approved_by,approved_at,mapping_confirmed_at,idempotency_key,expire_at)
                VALUES('8.8.8.8','input',300,'unknown',repeat('d',64),'restore-v1',
                '8b0280f8-6d76-4f81-b5cb-a4c0e10ee625',NOW(),NOW(),
                '0b0b9ed7-f5b1-46e5-a2ac-aa5bfdc1f59c',NOW()+interval '5 minutes') RETURNING id""")
            action_id = cursor.fetchone()[0]
            cursor.execute("""INSERT INTO response_execution_bindings(action_id,actor_id,actor_version,
                device_id,mapping_version,scope,reason,approval_expires_at)
                VALUES(%s,'8b0280f8-6d76-4f81-b5cb-a4c0e10ee625',3,%s,0,
                '{"asset":"restore-router"}','보존할 조치 승인 근거',NOW()+interval '5 minutes')""",
                (action_id, after["devices"][0]["id"]))
            cursor.execute("""INSERT INTO response_execution_claims(action_id,operation,request_hash,status,result,completed_at)
                VALUES(%s,'apply',repeat('e',64),'completed',
                '{"outcome":"unverified","observed":"unknown","backend":"shadow","detail":"대조 필요"}',NOW())""",
                (action_id,))
            cursor.execute("""INSERT INTO response_execution_claims(action_id,operation,request_hash,status)
                VALUES(%s,'remove',repeat('f',64),'prepared')""", (action_id,))
            cursor.execute("""INSERT INTO response_receipts(action_id,phase,outcome,detail)
                VALUES(%s,'apply','unverified','{"observed":"unknown","backend":"shadow"}')""", (action_id,))
        after_with_review = snapshot(databases[0])
        new_backup = tmp_path / "upgraded.dump"
        dump(databases[0], new_backup)
        restore(databases[2], new_backup)
        assert snapshot(databases[2]) == after_with_review
        with closing(psycopg2.connect(dbname=databases[2], **connection)) as conn, conn, conn.cursor() as cursor:
            cursor.execute("SET search_path TO netwatcher,public")
            cursor.execute("INSERT INTO devices(mac_address) VALUES ('02:00:00:00:00:02') RETURNING id")
            assert cursor.fetchone()[0] > after["devices"][0]["id"]
    finally:
        with admin.cursor() as cursor:
            for database in reversed(created):
                cursor.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))
        admin.close()
