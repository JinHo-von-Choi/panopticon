"""외부 사용자 식별자와 관리 계정의 명시적 연결을 저장한다."""

import uuid
from urllib.parse import urlsplit

from netwatcher.storage.user_accounts import AccountConflict, PUBLIC_COLUMNS, public

MAX_IDENTITIES = 10000


def issuer(value):
    if not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= 512:
        raise ValueError('Invalid OIDC issuer')
    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        raise ValueError('Invalid OIDC issuer')
    try:
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment):
            raise ValueError('Invalid OIDC issuer')
        _ = url.port
    except ValueError:
        raise ValueError('Invalid OIDC issuer') from None
    # iss와 sub는 공급자가 발급한 값을 그대로 비교한다.
    return value


def subject(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 255 or not value.isascii()
            or not value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('Invalid OIDC subject')
    return value


def identity(row):
    if row is None:
        return None
    result = dict(row)
    result['id'] = str(result['id'])
    result['user_id'] = str(result['user_id'])
    if hasattr(result['created_at'], 'isoformat'):
        result['created_at'] = result['created_at'].isoformat()
    return result


def version(value):
    if type(value) is not int or not 1 <= value < 2**63-1:
        raise ValueError('Invalid account version')


class OidcIdentities:
    def __init__(self, db):
        self.db = db

    async def for_user(self, user_id):
        rows = await self.db.pool.fetch('''SELECT * FROM oidc_identities
            WHERE user_id=$1 ORDER BY issuer,id''', uuid.UUID(str(user_id)))
        return [identity(row) for row in rows]

    async def snapshot(self, user_id):
        user_id = uuid.UUID(str(user_id))
        async with self.db.pool.acquire() as conn, conn.transaction(
                isolation='repeatable_read', readonly=True):
            account = await conn.fetchrow(f'SELECT {PUBLIC_COLUMNS} FROM user_accounts WHERE id=$1', user_id)
            if account is None:
                raise AccountConflict('account_missing')
            rows = await conn.fetch('SELECT * FROM oidc_identities WHERE user_id=$1 ORDER BY issuer,id', user_id)
        return {'user': public(account), 'identities': [identity(row) for row in rows]}

    async def resolve(self, issuer_value, subject_value):
        """서명·발급자·수신자 검증을 마친 ID 토큰의 계정 연결을 조회한다."""
        columns = ','.join('u.' + column for column in PUBLIC_COLUMNS.split(','))
        row = await self.db.pool.fetchrow(f'''SELECT {columns} FROM oidc_identities i
            JOIN user_accounts u ON u.id=i.user_id
            WHERE i.issuer=$1 AND i.subject=$2 AND u.enabled''',
            issuer(issuer_value), subject(subject_value))
        return public(row)

    async def link(self, user_id, expected_version, issuer_value, subject_value, actor):
        version(expected_version)
        issuer_value, subject_value = issuer(issuer_value), subject(subject_value)
        user_id = uuid.UUID(str(user_id))
        async with self.db.pool.acquire() as conn, conn.transaction():
            await conn.execute('LOCK TABLE user_accounts IN SHARE ROW EXCLUSIVE MODE')
            user = await self._account(conn, user_id, expected_version)
            if await conn.fetchval('SELECT count(*) FROM oidc_identities') >= MAX_IDENTITIES:
                raise AccountConflict('identity_capacity')
            if await conn.fetchval('SELECT EXISTS(SELECT 1 FROM oidc_identities WHERE issuer=$1 AND subject=$2)',
                                   issuer_value, subject_value):
                raise AccountConflict('subject_already_linked')
            if await conn.fetchval('SELECT EXISTS(SELECT 1 FROM oidc_identities WHERE issuer=$1 AND user_id=$2)',
                                   issuer_value, user_id):
                raise AccountConflict('issuer_already_linked')
            row = await conn.fetchrow('''INSERT INTO oidc_identities(id,user_id,issuer,subject,created_by)
                VALUES($1,$2,$3,$4,$5) RETURNING *''', uuid.uuid4(), user_id, issuer_value,
                subject_value, actor[:255])
            user = await self._bump(conn, user['id'], actor)
        return {'identity': identity(row), 'user': user}

    async def unlink(self, user_id, expected_version, identity_id, actor):
        version(expected_version)
        user_id, identity_id = uuid.UUID(str(user_id)), uuid.UUID(str(identity_id))
        async with self.db.pool.acquire() as conn, conn.transaction():
            await conn.execute('LOCK TABLE user_accounts IN SHARE ROW EXCLUSIVE MODE')
            user = await self._account(conn, user_id, expected_version)
            row = await conn.fetchrow('''DELETE FROM oidc_identities WHERE id=$1 AND user_id=$2
                RETURNING *''', identity_id, user_id)
            if row is None:
                raise AccountConflict('identity_missing')
            user = await self._bump(conn, user['id'], actor)
        return {'identity': identity(row), 'user': user}

    async def _account(self, conn, user_id, expected_version):
        row = await conn.fetchrow('SELECT id,version FROM user_accounts WHERE id=$1 FOR UPDATE', user_id)
        if row is None:
            raise AccountConflict('account_missing')
        if row['version'] != expected_version:
            raise AccountConflict('version_changed')
        return row

    async def _bump(self, conn, user_id, actor):
        row = await conn.fetchrow(f'''UPDATE user_accounts SET version=version+1,
            changed_by=$2,updated_at=NOW() WHERE id=$1 RETURNING {PUBLIC_COLUMNS}''', user_id, actor[:255])
        return public(row)
