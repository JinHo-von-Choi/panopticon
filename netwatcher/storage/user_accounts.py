"""개인 계정의 자격 증명과 역할·활성 상태를 관리한다."""
import asyncio
import re
import uuid

import bcrypt

USERNAME=re.compile(r'^[a-z0-9_.-]{1,64}$')
ROLES=frozenset({'viewer','analyst','admin'})
MAX_ACCOUNTS=1000
# 존재하지 않는 사용자도 같은 비용의 해시 검증을 거친다. 로그인용 계정이 아니다.
_DUMMY_HASH=b'$2b$12$3Zox24dDlbg7OnpyT.JWXeWe6joxF1QUj2D7het0yfnp29CsRLX7e'
PUBLIC_COLUMNS='id,username,role,enabled,version,created_at,updated_at,changed_by'


class AccountConflict(ValueError):
    pass


def username(value):
    if not isinstance(value,str) or not value.isascii():raise ValueError('Invalid username')
    value=value.lower()
    if not USERNAME.fullmatch(value):raise ValueError('Invalid username')
    return value


def valid_password(value):
    if not isinstance(value,str) or not 12<=len(value)<=72 or len(value.encode('utf-8'))>72 or '\x00' in value:
        raise ValueError('Password must be at least 12 characters and at most 72 UTF-8 bytes')
    return value


def public(row):
    if row is None:return None
    result=dict(row)
    result['id']=str(result['id'])
    for key in ('created_at','updated_at'):
        value=result[key]
        if hasattr(value,'isoformat'):result[key]=value.isoformat()
    return result


class UserAccounts:
    def __init__(self,db):self.db=db

    async def bootstrap(self,name,password_hash):
        name=username(name)
        if not isinstance(password_hash,str) or not password_hash.startswith(('$2b$','$2a$')):
            raise ValueError('Initial password must be a bcrypt hash')
        async with self.db.pool.acquire() as conn,conn.transaction():
            await conn.execute('LOCK TABLE user_accounts IN SHARE ROW EXCLUSIVE MODE')
            if await conn.fetchval('SELECT EXISTS(SELECT 1 FROM user_accounts)'):
                return None
            row=await conn.fetchrow(f"""INSERT INTO user_accounts(id,username,password_hash,role,changed_by)
                VALUES($1,$2,$3,'admin','initial_setup') RETURNING {PUBLIC_COLUMNS}""",uuid.uuid4(),name,password_hash)
            await conn.execute("""INSERT INTO audit_log(user_id,action,resource,details)
                VALUES('initial_setup','account_bootstrap','user_accounts',$1)""",
                {'account_id':str(row['id']),'username':row['username'],'role':'admin'})
        return public(row)

    async def get(self,user_id):
        return public(await self.db.pool.fetchrow(f'SELECT {PUBLIC_COLUMNS} FROM user_accounts WHERE id=$1',uuid.UUID(str(user_id))))

    async def get_by_username(self,name):
        return public(await self.db.pool.fetchrow(
            f'SELECT {PUBLIC_COLUMNS} FROM user_accounts WHERE username=$1',username(name)))

    async def list(self,*,offset=0,limit=50):
        async with self.db.pool.acquire() as conn,conn.transaction(isolation='repeatable_read',readonly=True):
            total=await conn.fetchval('SELECT count(*) FROM user_accounts')
            rows=await conn.fetch(f'SELECT {PUBLIC_COLUMNS} FROM user_accounts ORDER BY username,id LIMIT $1 OFFSET $2',limit,offset)
        return {'total':total,'users':[public(row) for row in rows]}

    async def create(self,name,password,role,actor):
        name=username(name);valid_password(password)
        if role not in ROLES:raise ValueError('Invalid role')
        password_hash=await asyncio.to_thread(bcrypt.hashpw,password.encode(),bcrypt.gensalt())
        async with self.db.pool.acquire() as conn,conn.transaction():
            await conn.execute('LOCK TABLE user_accounts IN SHARE ROW EXCLUSIVE MODE')
            if await conn.fetchval('SELECT count(*) FROM user_accounts')>=MAX_ACCOUNTS:raise AccountConflict('account_capacity')
            if not await conn.fetchval('SELECT EXISTS(SELECT 1 FROM user_accounts WHERE enabled AND role=\'admin\')') and role!='admin':
                raise AccountConflict('administrator_required')
            row=await conn.fetchrow(f'''INSERT INTO user_accounts(id,username,password_hash,role,changed_by)
                VALUES($1,$2,$3,$4,$5) ON CONFLICT(username) DO NOTHING RETURNING {PUBLIC_COLUMNS}''',
                uuid.uuid4(),name,password_hash.decode(),role,actor[:255])
            if row is None:raise AccountConflict('username_exists')
        return public(row)

    async def update(self,user_id,version,*,role,enabled,actor):
        if role not in ROLES or type(enabled) is not bool or type(version) is not int or not 1<=version<2**63-1:
            raise ValueError('Invalid account state')
        async with self.db.pool.acquire() as conn,conn.transaction():
            await conn.execute('LOCK TABLE user_accounts IN SHARE ROW EXCLUSIVE MODE')
            current=await conn.fetchrow('SELECT * FROM user_accounts WHERE id=$1 FOR UPDATE',uuid.UUID(str(user_id)))
            if current is None:raise AccountConflict('account_missing')
            if current['version']!=version:raise AccountConflict('version_changed')
            if current['enabled'] and current['role']=='admin' and (not enabled or role!='admin'):
                if await conn.fetchval("SELECT count(*) FROM user_accounts WHERE enabled AND role='admin'")<=1:
                    raise AccountConflict('last_administrator')
            row=await conn.fetchrow(f'''UPDATE user_accounts SET role=$2,enabled=$3,version=version+1,
                changed_by=$4,updated_at=NOW() WHERE id=$1 RETURNING {PUBLIC_COLUMNS}''',current['id'],role,enabled,actor[:255])
        return public(row)

    async def reset_password(self,user_id,version,password,actor):
        valid_password(password)
        if type(version) is not int or not 1<=version<2**63-1:raise ValueError('Invalid account version')
        hashed=await asyncio.to_thread(bcrypt.hashpw,password.encode(),bcrypt.gensalt())
        row=await self.db.pool.fetchrow(f'''UPDATE user_accounts SET password_hash=$3,version=version+1,
            changed_by=$4,updated_at=NOW() WHERE id=$1 AND version=$2 RETURNING {PUBLIC_COLUMNS}''',
            uuid.UUID(str(user_id)),version,hashed.decode(),actor[:255])
        if row is None:raise AccountConflict('version_changed_or_missing')
        return public(row)

    async def authenticate(self,name,password):
        try:name=username(name)
        except (ValueError,AttributeError):return None
        if not isinstance(password,str) or len(password.encode())>72 or '\x00' in password:return None
        row=await self.db.pool.fetchrow('SELECT * FROM user_accounts WHERE username=$1',name)
        stored_hash=row['password_hash'].encode() if row else _DUMMY_HASH
        try:verified=await asyncio.to_thread(bcrypt.checkpw,password.encode(),stored_hash)
        except ValueError:return None
        if not verified or row is None or not row['enabled']:return None
        # 해시 검증 중 역할 변경·비활성화가 있었는지 다시 확인한다.
        current=await self.db.pool.fetchrow(f'SELECT {PUBLIC_COLUMNS} FROM user_accounts WHERE id=$1 AND version=$2 AND enabled',row['id'],row['version'])
        return public(current)
