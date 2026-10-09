"""검증된 OIDC 로그인 요청과 명시적 개인 계정 연결을 이어 준다."""

import asyncio
import json
import logging
import os
from urllib.parse import urlsplit

import asyncpg

from netwatcher.storage.oidc_identities import OidcIdentities
from netwatcher.storage.oidc_login_requests import OidcLoginRequests, OidcRequestCapacity
from netwatcher.web.auth import AuthStateUnavailable
from netwatcher.web.oidc import OidcTokenInvalid
from netwatcher.web.oidc import OidcProvider

logger = logging.getLogger(__name__)


def configured_oidc_login(config, auth):
    settings = config.get('auth.oidc', {})
    if not isinstance(settings, dict):
        raise ValueError('Invalid OIDC configuration')
    enabled = settings.get('enabled', False)
    if enabled is False or enabled == 'false':
        return None
    if enabled is not True and enabled != 'true':
        raise ValueError('Invalid OIDC enabled setting')
    if 'client_secret' in settings:
        raise ValueError('Set OIDC client secret through NETWATCHER_OIDC_CLIENT_SECRET')
    provider = OidcProvider(settings.get('issuer'), settings.get('client_id'), settings.get('redirect_uri'),
        client_secret=os.environ.get('NETWATCHER_OIDC_CLIENT_SECRET') or None,
        endpoint_origins=settings.get('endpoint_origins', []))
    if urlsplit(provider.redirect_uri).path != '/api/auth/oidc/callback':
        raise ValueError('OIDC redirect URI must use /api/auth/oidc/callback')
    return OidcLogin(auth, provider)


class OidcLogin:
    def __init__(self, auth, provider):
        if auth is None or not auth.enabled or not auth.multi_user or auth.users is None:
            raise ValueError('OIDC requires managed authentication')
        self.auth, self.provider = auth, provider
        context = json.dumps([provider.issuer, provider.client_id, provider.redirect_uri])
        self.requests = OidcLoginRequests(auth.users.db, auth._secret, context)
        self.identities = OidcIdentities(auth.users.db)

    async def begin(self):
        pending = None
        url = None
        try:
            async with asyncio.timeout(15):
                pending = await self.requests.create()
                url = await self.provider.authorization_url(state=pending['state'], nonce=pending['nonce'],
                    challenge=pending['challenge'])
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OidcRequestCapacity, TimeoutError) as error:
            raise AuthStateUnavailable() from error
        finally:
            if pending is not None and url is None:
                try:
                    async with asyncio.timeout(2):
                        await self.requests.discard(pending['state'], pending['browser'])
                except (asyncpg.PostgresError, asyncpg.InterfaceError, TimeoutError):
                    logger.warning('OIDC request cleanup unavailable; expiry remains enforced')
        return {'url': url, 'browser': pending['browser']}

    async def finish(self, *, state, browser, code):
        try:
            async with asyncio.timeout(15):
                pending = await self.requests.consume(state, browser)
                if pending is None:
                    raise OidcTokenInvalid('Invalid login request')
                external = await self.provider.exchange(code=code, **pending)
                account = await self.identities.resolve(external['iss'], external['sub'])
                if account is None:
                    raise OidcTokenInvalid('Identity is not connected to an active account')
                token = self.auth.issue_account_token(account)
                # 계정 연결 조회 직후의 권한 변경도 로그인 완료 전에 확인한다.
                if await self.auth.verify_token_async(token) is None:
                    raise OidcTokenInvalid('Account changed during login')
                return token
        except (asyncpg.PostgresError, asyncpg.InterfaceError, TimeoutError) as error:
            raise AuthStateUnavailable() from error

    async def deliver(self, token, browser):
        try:
            async with asyncio.timeout(5):
                return await self.requests.deliver(token, browser)
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OidcRequestCapacity, TimeoutError) as error:
            raise AuthStateUnavailable() from error

    async def redeem(self, ticket, browser):
        try:
            async with asyncio.timeout(5):
                token = await self.requests.redeem(ticket, browser)
                if token is None or await self.auth.verify_token_async(token) is None:
                    raise OidcTokenInvalid('Invalid session delivery')
                return token
        except (asyncpg.PostgresError, asyncpg.InterfaceError, TimeoutError) as error:
            raise AuthStateUnavailable() from error
