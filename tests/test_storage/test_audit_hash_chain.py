"""실제 PostgreSQL 감사 로그 연결과 내용 변조 탐지."""

import asyncio
import hashlib
import json
from contextlib import closing
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import psycopg2
from psycopg2 import sql
from alembic import command
from alembic.config import Config as AlembicConfig

from netwatcher.web.audit_log import AuditLogger, GENESIS_HASH


@pytest.mark.asyncio
async def test_successive_entries_and_independent_digest(db):
    audit = AuditLogger(db.pool)
    assert await audit.log("관리자", "change" * 20, "/" + "r" * 220,
                           {"z": 1e30, "a": {"한글": [1, True, None]}}, "1" * 50)
    assert await audit.log("reader", "read", "/events")
    rows = await db.pool.fetch("SELECT * FROM audit_log ORDER BY id")
    first, second = rows
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["entry_hash"]
    assert first["entry_hash"] != GENESIS_HASH
    payload = (GENESIS_HASH + str(first["tenant_id"]) + "관리자" + "change" * 8 + "ch"
               + ("/" + "r" * 199)
               + json.dumps(first["details"], sort_keys=True,
                            separators=(",", ":"), ensure_ascii=False)
               + "1" * 45 + datetime.fromisoformat(first["created_at"]).astimezone(timezone.utc).isoformat())
    assert first["entry_hash"] == hashlib.sha256(payload.encode()).hexdigest()
    assert await audit.verify_chain() == {"valid": True, "count": 2}


@pytest.mark.asyncio
async def test_empty_chain(db):
    audit = AuditLogger(db.pool)
    assert await audit.verify_chain() == {"valid": True, "count": 0}
    assert await audit.verify_chain(uuid4()) == {"valid": True, "count": 0}


@pytest.mark.asyncio
async def test_interleaved_tenants_and_global_fallback(db):
    audit = AuditLogger(db.pool)
    a, b, c = uuid4(), uuid4(), uuid4()
    for tenant in (a, b, a, c, b):
        assert await audit.log("admin", "read", "/events", tenant_id=tenant)
    rows = await db.pool.fetch("SELECT * FROM audit_log ORDER BY id")
    assert rows[0]["prev_hash"] == GENESIS_HASH
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[2]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[3]["prev_hash"] == rows[2]["entry_hash"]
    assert rows[4]["prev_hash"] == rows[1]["entry_hash"]
    assert await audit.verify_chain() == {"valid": True, "count": 5}
    assert await audit.verify_chain(str(a)) == {"valid": True, "count": 2}
    assert await audit.verify_chain(b) == {"valid": True, "count": 2}
    assert await audit.verify_chain(c) == {"valid": True, "count": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation,reason", [
    ("details='{}'::jsonb", "entry_hash_mismatch"),
    ("user_id='attacker'", "entry_hash_mismatch"),
    ("action='delete'", "entry_hash_mismatch"),
    ("resource='/changed'", "entry_hash_mismatch"),
    ("ip='192.0.2.99'", "entry_hash_mismatch"),
    ("created_at=created_at + interval '1 second'", "entry_hash_mismatch"),
    ("entry_hash=repeat('f',64)", "entry_hash_mismatch"),
    ("prev_hash=repeat('f',64)", "prev_hash_mismatch"),
    ("tenant_id='00000000-0000-0000-0000-000000000001'", "entry_hash_mismatch"),
])
async def test_tampered_row_reports_exact_id(db, mutation, reason):
    audit = AuditLogger(db.pool)
    for i in range(3):
        assert await audit.log("admin", "write", "/events", {"index": i})
    broken_id = await db.pool.fetchval("SELECT id FROM audit_log ORDER BY id OFFSET 1 LIMIT 1")
    await db.pool.execute(f"UPDATE audit_log SET {mutation} WHERE id=$1", broken_id)
    assert await audit.verify_chain() == {
        "valid": False, "broken_id": broken_id, "count": 1, "reason": reason,
    }


@pytest.mark.asyncio
async def test_concurrent_writes_do_not_fork_chain(db):
    audit = AuditLogger(db.pool)
    assert all(await asyncio.gather(*(
        audit.log("admin", "write", "/events", {"index": i}) for i in range(20)
    )))
    assert await audit.verify_chain() == {"valid": True, "count": 20}


@pytest.mark.asyncio
async def test_deleted_middle_row_breaks_link(db):
    audit = AuditLogger(db.pool)
    for _ in range(3):
        assert await audit.log("admin", "read", "/events")
    ids = await db.pool.fetch("SELECT id FROM audit_log ORDER BY id")
    await db.pool.execute("DELETE FROM audit_log WHERE id=$1", ids[1]["id"])
    result = await audit.verify_chain()
    assert result["valid"] is False
    assert result["broken_id"] == ids[2]["id"]
    assert result["reason"] == "prev_hash_mismatch"


@pytest.mark.asyncio
async def test_legacy_zero_hash_is_not_verified(db):
    broken_id = await db.pool.fetchval(
        "INSERT INTO audit_log(user_id,action) VALUES ('legacy','read') RETURNING id"
    )
    assert await AuditLogger(db.pool).verify_chain() == {
        "valid": False, "broken_id": broken_id, "count": 0, "reason": "entry_hash_mismatch",
    }


def test_migration_upgrade_and_downgrade_preserve_legacy_rows(config, monkeypatch):
    pg = config.section("postgresql")
    schema = "hash_migration_" + uuid4().hex[:16]
    for key, value in {
        "HOST": pg["host"], "PORT": pg["port"], "NAME": pg["database"],
        "USER": pg["username"], "PASSWORD": pg["password"], "SEARCH_PATH": schema + ",public",
    }.items():
        monkeypatch.setenv("NETWATCHER_DB_" + key, str(value))
    monkeypatch.setenv("NETWATCHER_SKIP_DOTENV", "1")
    cfg = AlembicConfig("alembic.ini")
    with closing(psycopg2.connect(
        host=pg["host"], port=pg["port"], dbname=pg["database"],
        user=pg["username"], password=pg["password"],
    )) as connection:
        connection.autocommit = True
        try:
            command.upgrade(cfg, "038_multi_tenancy_rls")
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("SET search_path TO {},public").format(sql.Identifier(schema)))
                cursor.execute("INSERT INTO audit_log(action,details) VALUES ('legacy','{}')")
            for _ in range(2):
                command.upgrade(cfg, "039_audit_log_hash_chain")
                with connection.cursor() as cursor:
                    cursor.execute("SELECT action,details,prev_hash,entry_hash FROM audit_log")
                    assert cursor.fetchall() == [("legacy", {}, GENESIS_HASH, GENESIS_HASH)]
                    cursor.execute("""SELECT column_name,data_type,character_maximum_length,is_nullable
                        FROM information_schema.columns WHERE table_schema=%s AND table_name='audit_log'
                        AND column_name IN ('prev_hash','entry_hash') ORDER BY column_name""", (schema,))
                    assert cursor.fetchall() == [
                        ("entry_hash", "character varying", 64, "NO"),
                        ("prev_hash", "character varying", 64, "NO"),
                    ]
                command.downgrade(cfg, "038_multi_tenancy_rls")
                with connection.cursor() as cursor:
                    cursor.execute("SELECT action,details FROM audit_log")
                    assert cursor.fetchall() == [("legacy", {})]
                    cursor.execute("""SELECT count(*) FROM information_schema.columns
                        WHERE table_schema=%s AND table_name='audit_log'
                        AND column_name IN ('prev_hash','entry_hash')""", (schema,))
                    assert cursor.fetchone()[0] == 0
        finally:
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
