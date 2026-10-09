"""실제 PostgreSQL에서 테넌트 DDL, RLS 및 풀 컨텍스트 수명을 검증한다."""

from contextlib import closing
from uuid import UUID, uuid4

import asyncpg
import psycopg2
from psycopg2 import sql
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config as AlembicConfig

from netwatcher.storage.schemas import TENANT_RLS_SCHEMAS, TENANT_TABLES

ZERO_TENANT = UUID(int=0)
INSERTS = {
    "events": "INSERT INTO events(engine,severity,title,tenant_id) VALUES('test','INFO','test',$1) RETURNING id",
    "devices": "INSERT INTO devices(mac_address,tenant_id) VALUES($2,$1) RETURNING id",
    "incidents": "INSERT INTO incidents(severity,title,tenant_id) VALUES('INFO','test',$1) RETURNING id",
    "audit_log": "INSERT INTO audit_log(action,tenant_id) VALUES('test',$1) RETURNING id",
}


async def insert_row(connection, table, tenant, mac="02:00:00:00:00:01"):
    args = (tenant, mac) if table == "devices" else (tenant,)
    return await connection.fetchval(INSERTS[table], *args)


@pytest_asyncio.fixture
async def rls_role(db):
    """소유자·슈퍼유저 우회 없이 정책을 실행하는 격리된 역할."""
    role = "tenant_test_" + uuid4().hex
    schema = db._search_path.split(",")[0]
    async with db.pool.acquire() as connection:
        await connection.execute(f"CREATE ROLE {role} NOLOGIN NOSUPERUSER NOBYPASSRLS")
        try:
            await connection.execute(f"GRANT USAGE ON SCHEMA {schema} TO {role}")
            await connection.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON events,devices,incidents,audit_log TO {role}"
            )
            await connection.execute(f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA {schema} TO {role}")
            yield role
        finally:
            await connection.execute(f"DROP OWNED BY {role}")
            await connection.execute(f"DROP ROLE {role}")


@pytest.mark.asyncio
@pytest.mark.parametrize("table", TENANT_TABLES)
async def test_schema_default_index_and_idempotent_policy(db, table):
    async with db.pool.acquire() as connection:
        for statement in TENANT_RLS_SCHEMAS:
            await connection.execute(statement)
        column = await connection.fetchrow(
            "SELECT data_type, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_schema=current_schema() AND table_name=$1 AND column_name='tenant_id'", table,
        )
        assert column["data_type"] == "uuid"
        assert column["is_nullable"] == "NO"
        assert str(ZERO_TENANT) in column["column_default"]
        assert await connection.fetchval(
            "SELECT relrowsecurity FROM pg_class WHERE oid=$1::regclass", table,
        )
        assert await connection.fetchval(
            "SELECT am.amname FROM pg_class c JOIN pg_am am ON am.oid=c.relam "
            "WHERE c.oid=$1::regclass", f"idx_{table}_tenant_id",
        ) == "btree"
        assert await connection.fetchval(
            "SELECT count(*) FROM pg_policy WHERE polrelid=$1::regclass", table,
        ) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("table", TENANT_TABLES)
async def test_tenant_read_and_write_isolation(db, rls_role, table):
    tenant_a, tenant_b = uuid4(), uuid4()
    async with db.tenant_transaction("system") as connection:
        await connection.execute(f"SET LOCAL ROLE {rls_role}")
        first = await insert_row(connection, table, tenant_a)
        second = await insert_row(connection, table, tenant_b, "02:00:00:00:00:02")
        assert await connection.fetchval(f"SELECT count(*) FROM {table}") == 2

    async with db.tenant_transaction(tenant_a) as connection:
        await connection.execute(f"SET LOCAL ROLE {rls_role}")
        assert await connection.fetchval("SELECT row_security_active($1::regclass)", table)
        assert [r["id"] for r in await connection.fetch(f"SELECT id FROM {table}")] == [first]
        assert await connection.execute(
            f"UPDATE {table} SET tenant_id=$1 WHERE id=$2", tenant_a, second,
        ) == "UPDATE 0"
        assert await connection.execute(f"DELETE FROM {table} WHERE id=$1", second) == "DELETE 0"
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with connection.transaction():
                await insert_row(connection, table, tenant_b, "02:00:00:00:00:03")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            async with connection.transaction():
                await connection.execute(f"UPDATE {table} SET tenant_id=$1 WHERE id=$2", tenant_b, first)
        await insert_row(connection, table, tenant_a, "02:00:00:00:00:04")

    async with db.tenant_transaction(tenant_b) as connection:
        await connection.execute(f"SET LOCAL ROLE {rls_role}")
        assert [r["id"] for r in await connection.fetch(f"SELECT id FROM {table}")] == [second]


@pytest.mark.asyncio
@pytest.mark.parametrize("table", TENANT_TABLES)
async def test_missing_empty_and_invalid_context_fail_closed(db, rls_role, table):
    async with db.pool.acquire() as connection:
        await insert_row(connection, table, ZERO_TENANT)
        async with connection.transaction():
            await connection.execute(f"SET LOCAL ROLE {rls_role}")
            for value in (None, ""):
                if value is not None:
                    await connection.execute("SELECT set_config('app.current_tenant_id',$1,true)", value)
                assert await connection.fetchval(f"SELECT count(*) FROM {table}") == 0
                with pytest.raises(asyncpg.InsufficientPrivilegeError):
                    async with connection.transaction():
                        await insert_row(connection, table, ZERO_TENANT, "02:00:00:00:00:02")
            with pytest.raises(asyncpg.InvalidTextRepresentationError):
                async with connection.transaction():
                    await connection.execute("SELECT set_config('app.current_tenant_id','invalid',true)")
                    await connection.fetchval(f"SELECT count(*) FROM {table}")
            await db.set_tenant_id(ZERO_TENANT, connection=connection)
            assert await connection.fetchval(f"SELECT count(*) FROM {table}") == 1


@pytest.mark.asyncio
async def test_tenant_context_requires_transaction_and_valid_uuid(db):
    async with db.pool.acquire() as connection:
        with pytest.raises(RuntimeError, match="active transaction"):
            await db.set_tenant_id(uuid4(), connection=connection)
        async with connection.transaction():
            for invalid in ("", "invalid", "system'; SELECT 1; --"):
                with pytest.raises(ValueError):
                    await db.set_tenant_id(invalid, connection=connection)


@pytest.mark.asyncio
@pytest.mark.parametrize("rollback", [False, True])
async def test_local_context_restored_after_commit_or_rollback(db, rollback):
    tenant = uuid4()
    async with db.pool.acquire() as connection:
        before = await connection.fetchval("SELECT current_setting('app.current_tenant_id',true)")
        try:
            async with connection.transaction():
                await db.set_tenant_id(tenant, connection=connection)
                assert await connection.fetchval("SELECT current_setting('app.current_tenant_id',true)") == str(tenant)
                if rollback:
                    raise ValueError("rollback")
        except ValueError:
            assert rollback
        after = await connection.fetchval("SELECT current_setting('app.current_tenant_id',true)")
        assert (after or "") == (before or "")
    with pytest.raises(ValueError, match="rollback"):
        async with db.tenant_transaction(tenant):
            raise ValueError("rollback")
    async with db.pool.acquire() as connection:
        assert not await connection.fetchval("SELECT current_setting('app.current_tenant_id',true)")


def test_migration_preserves_legacy_rows_and_partition_indexes(config, monkeypatch):
    pg = config.section("postgresql")
    schema = "tenant_migration_" + uuid4().hex[:16]
    for key, value in {
        "HOST": pg["host"], "PORT": pg["port"], "NAME": pg["database"],
        "USER": pg["username"], "PASSWORD": pg["password"], "SEARCH_PATH": schema + ",public",
    }.items():
        monkeypatch.setenv("NETWATCHER_DB_" + key, str(value))
    monkeypatch.setenv("NETWATCHER_SKIP_DOTENV", "1")
    alembic_config = AlembicConfig("alembic.ini")
    with closing(psycopg2.connect(
        host=pg["host"], port=pg["port"], dbname=pg["database"],
        user=pg["username"], password=pg["password"],
    )) as connection:
        connection.autocommit = True
        try:
            command.upgrade(alembic_config, "037_sensor_claim_retention")
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("SET search_path TO {},public").format(sql.Identifier(schema)))
                cursor.execute("INSERT INTO events(engine,severity,title) VALUES('legacy','INFO','legacy')")
                cursor.execute("INSERT INTO devices(mac_address) VALUES('02:00:00:00:00:01')")
                cursor.execute("INSERT INTO incidents(severity,title) VALUES('INFO','legacy')")
                cursor.execute("INSERT INTO audit_log(action) VALUES('legacy')")
            for _ in range(2):
                command.upgrade(alembic_config, "038_multi_tenancy_rls")
                with connection.cursor() as cursor:
                    for table in TENANT_TABLES:
                        cursor.execute(sql.SQL("SELECT tenant_id FROM {}").format(sql.Identifier(table)))
                        assert cursor.fetchall() == [(str(ZERO_TENANT),)]
                        cursor.execute("SELECT relrowsecurity FROM pg_class WHERE oid=%s::regclass", (table,))
                        assert cursor.fetchone()[0]
                    cursor.execute("""SELECT EXISTS (
                        SELECT 1 FROM pg_index ix
                        JOIN pg_class idx ON idx.oid=ix.indexrelid
                        JOIN pg_am am ON am.oid=idx.relam
                        JOIN pg_attribute a ON a.attrelid=ix.indrelid
                            AND a.attnum=ix.indkey[0]
                        WHERE ix.indrelid='events'::regclass
                            AND ix.indexrelid='idx_events_tenant_id'::regclass
                            AND ix.indisvalid AND ix.indisready
                            AND ix.indnatts=1 AND a.attname='tenant_id'
                            AND ix.indpred IS NULL AND am.amname='btree'
                    )""")
                    assert cursor.fetchone()[0]
                    # 모든 기존 파티션에 부모 인덱스와 연결된 유효한 인덱스가 있어야 한다.
                    cursor.execute("""SELECT count(*) FROM pg_inherits partitions
                        WHERE partitions.inhparent='events'::regclass
                            AND NOT EXISTS (
                                SELECT 1 FROM pg_index ix
                                JOIN pg_inherits indexes ON indexes.inhrelid=ix.indexrelid
                                WHERE ix.indrelid=partitions.inhrelid
                                    AND indexes.inhparent='idx_events_tenant_id'::regclass
                                    AND ix.indisvalid AND ix.indisready
                            )""")
                    assert cursor.fetchone()[0] == 0
                command.downgrade(alembic_config, "037_sensor_claim_retention")
                with connection.cursor() as cursor:
                    for table in TENANT_TABLES:
                        cursor.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table)))
                        assert cursor.fetchone()[0] == 1
                        cursor.execute("SELECT relrowsecurity FROM pg_class WHERE oid=%s::regclass", (table,))
                        assert not cursor.fetchone()[0]
        finally:
            with connection.cursor() as cursor:
                cursor.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema)))
