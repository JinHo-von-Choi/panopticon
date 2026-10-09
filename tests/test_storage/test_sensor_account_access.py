"""권한이 없는 실제 DB 계정으로 비밀번호 격리와 폐기 경쟁을 검증한다."""

import secrets
from uuid import uuid4

import asyncpg
import pytest

from netwatcher.storage.user_accounts import UserAccounts


@pytest.mark.asyncio
async def test_restricted_sensor_can_lock_status_but_cannot_read_hash_or_change_account(db,config):
    role='sensor_test_'+uuid4().hex[:12]
    password=secrets.token_hex(32)
    schema=config.get('postgresql.search_path').split(',')[0]
    account=await UserAccounts(db).create('account-lock','a-strong-test-password-123','admin','test')
    pg=config.section('postgresql')
    conn=None
    try:
        async with db.pool.acquire() as admin:
            # 식별자는 시험 안에서 생성한다. 비밀번호는 SQL 인자로 전달한다.
            await admin.execute(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT')
            await admin.execute('SELECT set_config(\'sensor.test_password\',$1,false)',password)
            await admin.execute(f'''DO $$BEGIN EXECUTE format('ALTER ROLE %I PASSWORD %L',
                '{role}',current_setting('sensor.test_password')); END $$''')
            await admin.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO "{role}"')
        conn=await asyncpg.connect(host=pg['host'],port=pg['port'],database=pg['database'],
            user=role,password=password,server_settings={'search_path':schema+',public'})
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch('SELECT * FROM sensor_account_for_share($1)',account['id'])
        await db.pool.execute(f'GRANT EXECUTE ON FUNCTION sensor_account_for_share(uuid) TO "{role}"')
        async with conn.transaction():
            state=await conn.fetchrow('SELECT * FROM sensor_account_for_share($1)',account['id'])
            assert dict(state)=={'role':'admin','enabled':True,'version':1}
            async with db.pool.acquire() as admin,admin.transaction():
                await admin.execute("SET LOCAL lock_timeout='100ms'")
                with pytest.raises(asyncpg.LockNotAvailableError):
                    await admin.execute('UPDATE user_accounts SET enabled=false WHERE id=$1',account['id'])
        await db.pool.execute('UPDATE user_accounts SET enabled=false,version=version+1 WHERE id=$1',account['id'])
        state=await conn.fetchrow('SELECT * FROM sensor_account_for_share($1)',account['id'])
        assert state['enabled'] is False and state['version']==2
        for query in ('SELECT password_hash FROM user_accounts',
            "UPDATE user_accounts SET role='admin'",'CREATE TABLE sensor_escape(id int)'):
            with pytest.raises(asyncpg.InsufficientPrivilegeError):await conn.execute(query)
        assert await conn.fetchrow('SELECT * FROM sensor_account_for_share($1)',uuid4()) is None
    finally:
        if conn is not None:await conn.close()
        async with db.pool.acquire() as admin:
            await admin.execute(f'DROP OWNED BY "{role}"')
            await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
