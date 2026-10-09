"""OIDC ID 토큰의 공개 키 서명과 로그인 요청에 묶인 클레임을 검증한다."""

import base64
import hashlib
import hmac
import json
import time
import asyncio
import re
import ssl
from urllib.parse import urlsplit, urlencode, quote_plus

import jwt
import aiohttp
from jwt.algorithms import RSAAlgorithm

from netwatcher.storage.oidc_identities import issuer, subject

MAX_TOKEN_BYTES = 16384
MAX_KEYS = 32


class OidcTokenInvalid(ValueError):
    """외부 토큰을 거절한다. 토큰·클레임·공급자 응답은 예외에 넣지 않는다."""


class OidcProviderUnavailable(RuntimeError):
    """공급자 연결·메타데이터·공개 키를 확인할 수 없다."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OidcTokenInvalid('Invalid ID token')
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError('Invalid JSON')


def _segment(value):
    try:
        decoded = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        return json.loads(decoded, object_pairs_hook=_unique_object,
                          parse_constant=_reject_json_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise OidcTokenInvalid('Invalid ID token') from None


class OidcTokenVerifier:
    """設定した供給者の公開鍵で検証する。ネットワーク接続は行わない。"""

    def __init__(self, issuer_value, client_id, jwks):
        self.issuer = issuer(issuer_value)
        if (not isinstance(client_id, str) or not 1 <= len(client_id) <= 255
                or not client_id.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in client_id)):
            raise ValueError('Invalid OIDC client ID')
        self.client_id = client_id
        if not isinstance(jwks, dict) or not isinstance(jwks.get('keys'), list) or not 1 <= len(jwks['keys']) <= MAX_KEYS:
            raise ValueError('Invalid OIDC key set')
        self.keys = {}
        for value in jwks['keys']:
            if not isinstance(value, dict):
                raise ValueError('Invalid OIDC key set')
            if value.get('kty') != 'RSA' or value.get('use', 'sig') != 'sig' or value.get('alg', 'RS256') != 'RS256':
                continue
            kid = value.get('kid')
            if (not isinstance(kid, str) or not 1 <= len(kid) <= 128 or not kid.isascii()
                    or any(ord(c) <= 32 or ord(c) == 127 for c in kid) or kid in self.keys):
                raise ValueError('Invalid OIDC key set')
            if ('key_ops' in value and value['key_ops'] != ['verify']) or any(
                    field in value for field in ('d', 'p', 'q', 'dp', 'dq', 'qi', 'oth')):
                raise ValueError('Invalid OIDC key set')
            if any(not isinstance(value.get(field), str) or not 1 <= len(value[field]) <= 1500
                   for field in ('n', 'e')):
                raise ValueError('Invalid OIDC key set')
            try:
                key = RSAAlgorithm.from_jwk({'kty': 'RSA', 'n': value['n'], 'e': value['e']})
            except (ValueError, TypeError, jwt.InvalidKeyError):
                raise ValueError('Invalid OIDC key set') from None
            if not 2048 <= key.key_size <= 8192:
                raise ValueError('Invalid OIDC key set')
            self.keys[kid] = key
        if not self.keys:
            raise ValueError('No supported OIDC signing key')

    def verify(self, token, *, nonce, access_token=None, code=None):
        """RS256 서명·iss·aud·azp·시각·sub·nonce와 선택적 해시를 검증한다."""
        try:
            return self._verify(token, nonce, access_token, code)
        except (ValueError, TypeError, KeyError, OverflowError, jwt.InvalidTokenError):
            raise OidcTokenInvalid('Invalid ID token') from None

    def _verify(self, token, nonce, access_token, code):
        if (not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN_BYTES
                or not isinstance(nonce, str) or not 16 <= len(nonce) <= 255 or not nonce.isascii()):
            raise OidcTokenInvalid('Invalid ID token')
        parts = token.split('.')
        if len(parts) != 3:
            raise OidcTokenInvalid('Invalid ID token')
        header, raw = _segment(parts[0]), _segment(parts[1])
        if not isinstance(header, dict) or not isinstance(raw, dict):
            raise OidcTokenInvalid('Invalid ID token')
        if header.get('alg') != 'RS256' or any(field in header for field in ('crit', 'jku', 'x5u', 'jwk', 'b64')):
            raise OidcTokenInvalid('Invalid ID token')
        kid = header.get('kid')
        if not isinstance(kid, str) or kid not in self.keys:
            raise OidcTokenInvalid('Invalid ID token')
        claims = jwt.decode(token, self.keys[kid], algorithms=['RS256'], issuer=self.issuer,
            audience=self.client_id, options={'require': ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce']})
        for field in ('exp', 'iat', 'nbf', 'auth_time'):
            if field in claims and type(claims[field]) is not int:
                raise OidcTokenInvalid('Invalid ID token')
        now = time.time()
        if (claims['exp'] <= claims['iat'] or claims['iat'] > now
                or ('auth_time' in claims and not 0 <= claims['auth_time'] <= now)):
            raise OidcTokenInvalid('Invalid ID token')
        subject(claims['sub'])
        audiences = claims['aud'] if isinstance(claims['aud'], list) else [claims['aud']]
        if not 1 <= len(audiences) <= 16 or any(not isinstance(a, str) or not a for a in audiences):
            raise OidcTokenInvalid('Invalid ID token')
        if (len(audiences) > 1 or 'azp' in claims) and claims.get('azp') != self.client_id:
            raise OidcTokenInvalid('Invalid ID token')
        if (not isinstance(claims['nonce'], str) or not claims['nonce'].isascii()
                or not hmac.compare_digest(claims['nonce'], nonce)):
            raise OidcTokenInvalid('Invalid ID token')
        for claim, original in (('at_hash', access_token), ('c_hash', code)):
            if claim not in claims:
                continue
            if (not isinstance(original, str) or not 1 <= len(original) <= MAX_TOKEN_BYTES
                    or not original.isascii() or not isinstance(claims[claim], str)
                    or not claims[claim].isascii()):
                raise OidcTokenInvalid('Invalid ID token')
            digest = hashlib.sha256(original.encode('ascii')).digest()[:16]
            expected = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
            if not hmac.compare_digest(claims[claim], expected):
                raise OidcTokenInvalid('Invalid ID token')
        return claims


class OidcProvider:
    """설정한 발급자에만 HTTPS로 연결하는 Authorization Code 클라이언트."""

    def __init__(self, issuer_value, client_id, redirect_uri, *, client_secret=None, ssl_context=None, endpoint_origins=()):
        self.issuer = issuer(issuer_value)
        self.redirect_uri = issuer(redirect_uri)
        if (not isinstance(client_id, str) or not 1 <= len(client_id) <= 255 or not client_id.isascii()
                or any(ord(c) <= 32 or ord(c) == 127 for c in client_id)):
            raise ValueError('Invalid OIDC client ID')
        if client_secret is not None and (not isinstance(client_secret, str)
                or not 1 <= len(client_secret) <= 4096 or not client_secret.isascii()
                or any(ord(c) < 32 or ord(c) == 127 for c in client_secret)):
            raise ValueError('Invalid OIDC client secret')
        self.client_id, self._secret = client_id, client_secret
        self._origins = {self._origin(self.issuer)}
        if not isinstance(endpoint_origins, (tuple, list)) or len(endpoint_origins) > 8:
            raise ValueError('Invalid OIDC endpoint origins')
        for address in endpoint_origins:
            address = issuer(address)
            if urlsplit(address).path not in ('', '/'):
                raise ValueError('OIDC endpoint origin must not contain a path')
            self._origins.add(self._origin(address))
        if ssl_context is not None:
            if (not isinstance(ssl_context, ssl.SSLContext) or not ssl_context.check_hostname
                    or ssl_context.verify_mode != ssl.CERT_REQUIRED):
                raise ValueError('OIDC requires TLS verification')
        self._ssl = ssl_context if ssl_context is not None else True
        self._metadata = None
        self._verifier = None
        self._expires = 0
        self._last_key_refresh = float('-inf')
        self._lock = asyncio.Lock()

    @staticmethod
    def _origin(address):
        url = urlsplit(address)
        return url.scheme, url.hostname, url.port or 443

    def _endpoint(self, value):
        value = issuer(value)
        if self._origin(value) not in self._origins:
            raise ValueError('OIDC endpoint origin differs from issuer')
        return value

    async def _json(self, method, url, *, data=None, headers=None):
        try:
            async with asyncio.timeout(5), aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5),
                    trust_env=False, cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False) as session:
                async with session.request(method, url, data=data, headers=headers,
                        ssl=self._ssl, allow_redirects=False) as response:
                    if response.status != 200 or (response.content_type != 'application/json'
                            and not response.content_type.endswith('+json')):
                        raise OidcProviderUnavailable('OIDC provider unavailable')
                    chunks, size = [], 0
                    async for chunk in response.content.iter_chunked(8192):
                        size += len(chunk)
                        if size > 65536:
                            raise OidcProviderUnavailable('OIDC provider unavailable')
                        chunks.append(chunk)
                    result = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_unique_object,
                        parse_constant=_reject_json_constant)
                    if not isinstance(result, dict):
                        raise ValueError()
                    return result
        except (aiohttp.ClientError, TimeoutError, ValueError, UnicodeError, RecursionError):
            raise OidcProviderUnavailable('OIDC provider unavailable') from None

    async def _load(self):
        async with self._lock:
            if self._metadata is not None and time.monotonic() < self._expires:
                return
            try:
                metadata = await self._json('GET', self.issuer.rstrip('/') + '/.well-known/openid-configuration')
                if metadata.get('issuer') != self.issuer:
                    raise ValueError()
                for field, needed in [('response_types_supported', 'code'),
                        ('id_token_signing_alg_values_supported', 'RS256'),
                        ('code_challenge_methods_supported', 'S256')]:
                    if not isinstance(metadata.get(field), list) or needed not in metadata[field]:
                        raise ValueError()
                if 'grant_types_supported' in metadata and (not isinstance(metadata['grant_types_supported'], list)
                        or 'authorization_code' not in metadata['grant_types_supported']):
                    raise ValueError()
                methods = metadata.get('token_endpoint_auth_methods_supported', ['client_secret_basic'])
                wanted = 'client_secret_basic' if self._secret is not None else 'none'
                if not isinstance(methods, list) or wanted not in methods:
                    raise ValueError()
                checked = {field: self._endpoint(metadata.get(field))
                    for field in ('authorization_endpoint', 'token_endpoint', 'jwks_uri')}
                jwks = await self._json('GET', checked['jwks_uri'])
                verifier = OidcTokenVerifier(self.issuer, self.client_id, jwks)
            except (ValueError, TypeError):
                raise OidcProviderUnavailable('OIDC provider unavailable') from None
            self._metadata, self._verifier = checked, verifier
            self._expires = time.monotonic() + 300
            self._last_key_refresh = float('-inf')

    async def authorization_url(self, *, state, nonce, challenge):
        for value in (state, nonce, challenge):
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', value):
                raise ValueError('Invalid OIDC login request')
        await self._load()
        return self._metadata['authorization_endpoint'] + '?' + urlencode({
            'client_id': self.client_id, 'redirect_uri': self.redirect_uri,
            'response_type': 'code', 'scope': 'openid', 'state': state, 'nonce': nonce,
            'code_challenge': challenge, 'code_challenge_method': 'S256'})

    async def exchange(self, *, code, verifier, nonce):
        if (not isinstance(code, str) or not 1 <= len(code) <= 4096 or not code.isascii()
                or any(ord(c) <= 32 or ord(c) == 127 for c in code)
                or not isinstance(verifier, str) or not re.fullmatch(r'[A-Za-z0-9_.~-]{43,128}', verifier)):
            raise OidcTokenInvalid('Invalid authorization response')
        await self._load()
        data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': self.redirect_uri,
                'code_verifier': verifier, 'client_id': self.client_id}
        headers = {'Authorization': aiohttp.encode_basic_auth(quote_plus(self.client_id), quote_plus(self._secret))} if self._secret is not None else None
        result = await self._json('POST', self._metadata['token_endpoint'], data=data, headers=headers)
        token = result.get('id_token')
        # 키가 바뀐 경우 발급자가 지정한 JWKS만 다시 읽는다. 갱신 간격을 제한한다.
        try:
            header = jwt.get_unverified_header(token) if isinstance(token, str) and len(token) <= MAX_TOKEN_BYTES else {}
        except jwt.InvalidTokenError:
            header = {}
        kid = header.get('kid')
        if (header.get('alg') == 'RS256' and isinstance(kid, str) and 1 <= len(kid) <= 128
                and kid.isascii() and kid not in self._verifier.keys
                and not any(field in header for field in ('crit', 'jku', 'x5u', 'jwk', 'b64'))):
            async with self._lock:
                if time.monotonic() - self._last_key_refresh >= 5:
                    self._last_key_refresh = time.monotonic()
                    jwks = await self._json('GET', self._metadata['jwks_uri'])
                    try:
                        refreshed = OidcTokenVerifier(self.issuer, self.client_id, jwks)
                    except ValueError:
                        raise OidcProviderUnavailable('OIDC provider unavailable') from None
                    self._verifier = refreshed
        checked = self._verifier.verify(token, nonce=nonce, access_token=result.get('access_token'), code=code)
        return {'iss': checked['iss'], 'sub': checked['sub']}
