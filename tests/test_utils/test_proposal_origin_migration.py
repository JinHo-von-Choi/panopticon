"""기존 제안을 보존하면서 센서 출처 제약을 추가·제거한다."""

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import psycopg2
from psycopg2 import sql
import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_proposal_origin_upgrade_preserves_legacy_rows_and_checks_complete_origin(config, tmp_path):
    pg = config.section("postgresql")
    schema = "proposal_origin_" + uuid4().hex
    env = os.environ.copy()
    env.update({"NETWATCHER_SKIP_DOTENV": "1", "NETWATCHER_DB_HOST": str(pg["host"]),
                "NETWATCHER_DB_PORT": str(pg["port"]), "NETWATCHER_DB_NAME": pg["database"],
                "NETWATCHER_DB_USER": pg["username"], "NETWATCHER_DB_PASSWORD": pg["password"],
                "NETWATCHER_DB_SEARCH_PATH": schema + ",public"})
    with closing(psycopg2.connect(host=pg["host"], port=pg["port"], dbname=pg["database"],
                                user=pg["username"], password=pg["password"], connect_timeout=5)) as conn:
        conn.autocommit = True
        with conn.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            cursor.execute(sql.SQL("SET search_path TO {}, public").format(sql.Identifier(schema)))
            def migrate(operation, revision):
                result = subprocess.run([sys.executable, "-m", "alembic", operation, revision],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=90)
                (tmp_path / (operation + "-" + revision + ".log")).write_text(result.stdout + result.stderr)
                assert result.returncode == 0, "소유한 시험 스키마의 마이그레이션 실패"
            def row():
                cursor.execute("SELECT row_to_json(p) FROM config_proposals p WHERE id=1")
                return cursor.fetchone()[0]
            try:
                migrate("upgrade", "034_sensor_control_claims")
                cursor.execute("""INSERT INTO config_proposals(engine,params,reason,before)
                    VALUES('port_scan',%s,'정상 업무 확인',%s)""", (json.dumps({"threshold": 10}), json.dumps({"threshold": 5})))
                original = row()
                migrate("upgrade", "035_proposal_sensor_origin")
                upgraded = row()
                assert {key: upgraded[key] for key in original} == original
                assert all(upgraded[key] is None for key in ("sensor_id", "sensor_owner", "source_version"))
                with pytest.raises(psycopg2.errors.CheckViolation):
                    cursor.execute("""INSERT INTO config_proposals(engine,params,sensor_id)
                        VALUES('port_scan','{"threshold":10}'::jsonb,'office')""")
                cursor.execute("""INSERT INTO config_proposals(engine,params,sensor_id,sensor_owner,source_version)
                    VALUES('port_scan','{"threshold":10}'::jsonb,'office',%s,%s)""", (str(uuid4()), "a" * 64))
                with pytest.raises(psycopg2.errors.CheckViolation):
                    cursor.execute("UPDATE config_proposals SET source_version='invalid' WHERE sensor_id='office'")
                migrate("downgrade", "034_sensor_control_claims")
                assert row() == original
                migrate("upgrade", "035_proposal_sensor_origin")
                assert {key: row()[key] for key in original} == original
            finally:
                cursor.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
