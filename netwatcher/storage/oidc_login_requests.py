"""OIDC 로그인 상태를 암호화하고 브라우저·유효 기간·일회 사용에 묶는다."""

import base64
import hashlib
import json
import re
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TOKEN = re.compile(r'^[A-Za-z0-9_-]{43}$')
TTL_SECONDS = 300
MAX_PENDING = 1024
DELIVERY_TTL_SECONDS = 30


class OidcRequestCapacity(RuntimeError):
    """진행 중인 로그인 요청 한도를 넘었다."""


def digest(value):
    return hashlib.sha256(value.encode('ascii')).hexdigest()


class OidcLoginRequests:
    def __init__(self, db, secret, context):
        if not isinstance(secret, str) or not 32 <= len(secret.encode('utf-8')) <= 4096:
            raise ValueError('OIDC requires a persistent secret of at least 32 bytes')
        if not isinstance(context, str) or not context:
            raise ValueError('Invalid OIDC request context')
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
            info=b'panopticon:oidc-login-state:v1').derive(secret.encode('utf-8'))
        self._cipher = Fernet(base64.urlsafe_b64encode(key))
        self._context = hashlib.sha256(context.encode('utf-8')).hexdigest()
        self.db = db

    async def create(self):
        state, browser, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
        value = {'context': self._context, 'kind': 'login', 'nonce': nonce, 'verifier': verifier}
        await self._store(state, browser, value, TTL_SECONDS)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
        return {'state': state, 'browser': browser, 'nonce': nonce, 'challenge': challenge}

    async def _store(self, state, browser, value, ttl):
        protected = self._cipher.encrypt(json.dumps(value).encode('utf-8')).decode('ascii')
        async with self.db.pool.acquire() as conn, conn.transaction():
            await conn.execute('LOCK TABLE oidc_login_requests IN SHARE ROW EXCLUSIVE MODE')
            await conn.execute('DELETE FROM oidc_login_requests WHERE expires_at <= clock_timestamp()')
            if await conn.fetchval('SELECT count(*) FROM oidc_login_requests') >= MAX_PENDING:
                raise OidcRequestCapacity('Too many pending OIDC requests')
            await conn.execute('''INSERT INTO oidc_login_requests(state_hash,browser_hash,protected,expires_at)
                VALUES($1,$2,$3,clock_timestamp()+make_interval(secs=>$4))''',
                digest(state), digest(browser), protected, ttl)

    async def deliver(self, token, browser):
        if (not isinstance(token, str) or not token.isascii() or not 1 <= len(token) <= 2048
                or not isinstance(browser, str) or not TOKEN.fullmatch(browser)):
            raise ValueError('Invalid OIDC session delivery')
        ticket = secrets.token_urlsafe(32)
        await self._store(ticket, browser, {'context': self._context, 'kind': 'session', 'token': token}, DELIVERY_TTL_SECONDS)
        return ticket

    async def redeem(self, ticket, browser):
        value = await self._consume(ticket, browser, DELIVERY_TTL_SECONDS)
        if (value is None or value.get('kind') != 'session' or not isinstance(value.get('token'), str)
                or not value['token'].isascii() or not 1 <= len(value['token']) <= 2048):
            return None
        return value['token']

    async def discard(self, state, browser):
        if all(isinstance(v, str) and TOKEN.fullmatch(v) for v in (state, browser)):
            await self.db.pool.execute('DELETE FROM oidc_login_requests WHERE state_hash=$1 AND browser_hash=$2',
                digest(state), digest(browser))

    async def consume(self, state, browser):
        value = await self._consume(state, browser, TTL_SECONDS)
        if (value is None or value.get('kind', 'login') != 'login'
                or any(not isinstance(value.get(field), str) or not TOKEN.fullmatch(value[field])
                       for field in ('nonce', 'verifier'))):
            return None
        return {'nonce': value['nonce'], 'verifier': value['verifier']}

    async def _consume(self, state, browser, ttl):
        if not all(isinstance(v, str) and TOKEN.fullmatch(v) for v in (state, browser)):
            return None
        # DELETE가 먼저 커밋되어 다른 프로세스에서도 같은 요청을 재사용할 수 없다.
        row = await self.db.pool.fetchrow('''DELETE FROM oidc_login_requests
            WHERE state_hash=$1 AND browser_hash=$2 AND expires_at>clock_timestamp() RETURNING protected''',
            digest(state), digest(browser))
        if row is None:
            return None
        try:
            value = json.loads(self._cipher.decrypt(row['protected'].encode('ascii'), ttl=ttl))
            if not isinstance(value, dict) or value.get('context') != self._context:
                return None
        except (InvalidToken, ValueError, UnicodeError, TypeError):
            return None
        return value
