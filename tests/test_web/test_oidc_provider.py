"""소유한 HTTPS 공급자에서 발견·코드 교환·서명과 키 교체를 확인한다."""

import base64
import hashlib
import ipaddress
import json
import secrets
import socket
import ssl
import time
import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, parse_qs

import jwt
import pytest
import pytest_asyncio
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from netwatcher.web.oidc import OidcProvider, OidcProviderUnavailable, OidcTokenInvalid


@pytest_asyncio.fixture
async def provider(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'OIDC owned fixture')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256()))
    certfile, keyfile = tmp_path / 'certificate.pem', tmp_path / 'private.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_ssl.load_cert_chain(certfile, keyfile)
    client_ssl = ssl.create_default_context(cafile=str(certfile))
    sock = socket.socket(); sock.bind(('127.0.0.1', 0))
    origin = 'https://127.0.0.1:' + str(sock.getsockname()[1])
    nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    state = {'issuer': origin, 'key': key, 'kid': 'initial', 'requests': [], 'fault': None,
             'nonce': nonce, 'verifier': verifier, 'codes': {'valid-code'}, 'client_secret': None}

    async def handler(request):
        state['requests'].append((request.method, request.path))
        if state['fault'] == 'slow':
            await asyncio.sleep(5.2)
        if state['fault'] == 'redirect':
            raise web.HTTPFound(origin + '/redirect-target')
        if state['fault'] == 'oversize':
            return web.Response(body=b' ' * 65537, content_type='application/json')
        if state['fault'] == 'invalid_json':
            return web.Response(text='{"issuer":1,"issuer":2}', content_type='application/json')
        if request.path == '/.well-known/openid-configuration':
            return web.json_response({'issuer': origin + '/' if state['fault'] == 'wrong_issuer' else state['issuer'], 'authorization_endpoint': origin + '/authorize',
                'token_endpoint': ('https://untrusted.example/token' if state['fault'] == 'cross_origin' else origin + '/token'),
                'jwks_uri': origin + '/keys', 'response_types_supported': ['code'],
                'id_token_signing_alg_values_supported': ['RS256'],
                'code_challenge_methods_supported': [] if state['fault'] == 'no_pkce' else ['S256'],
                'token_endpoint_auth_methods_supported': ['none', 'client_secret_basic']})
        if request.path == '/keys':
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(state['key'].public_key()))
            return web.json_response({'keys': [jwk | {'kid': state['kid'], 'alg': 'RS256'}]})
        if request.path == '/token':
            data = await request.post()
            assert data['grant_type'] == 'authorization_code' and data['client_id'] == 'fixture-client'
            assert data['redirect_uri'] == 'https://console.example/api/auth/oidc/callback'
            if state.get('challenge'):
                actual = base64.urlsafe_b64encode(hashlib.sha256(data['code_verifier'].encode()).digest()).rstrip(b'=').decode()
                assert actual == state['challenge']
            else:
                assert data['code_verifier'] == state['verifier']
            assert 'client_secret' not in data
            if state['client_secret'] is not None:
                assert request.headers['Authorization'] == 'Basic ' + base64.b64encode(b'fixture-client:fixture%3Asecret%2Bvalue').decode()
            if data['code'] not in state['codes']:
                return web.json_response({'error': 'invalid_grant'}, status=400)
            state['codes'].remove(data['code'])
            issued = {'iss': origin, 'aud': 'fixture-client', 'sub': 'external-subject',
                      'iat': int(time.time()) - 1, 'exp': int(time.time()) + 300,
                      'nonce': state['nonce'], 'role': 'admin'}
            if state['fault'] == 'wrong_nonce':
                issued['nonce'] = 'wrong-nonce-32-characters-value'
            token = jwt.encode(issued, state['key'], algorithm='RS256',
                headers={'kid': state['kid']} | state.get('header_extra', {}))
            return web.json_response({'id_token': token, 'access_token': 'fixture-access', 'token_type': 'Bearer'})
        return web.json_response({'error': 'unexpected'}, status=404)

    app = web.Application(); app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app); await runner.setup()
    site = web.SockSite(runner, sock, ssl_context=server_ssl); await site.start()
    client = OidcProvider(origin, 'fixture-client', 'https://console.example/api/auth/oidc/callback', ssl_context=client_ssl)
    try:
        yield client, state, client_ssl
    finally:
        await runner.cleanup()
        sock.close()


@pytest.mark.asyncio
async def test_real_tls_discovery_pkce_code_exchange_and_single_use(provider):
    client, state, _ = provider
    challenge = base64.urlsafe_b64encode(hashlib.sha256(state['verifier'].encode()).digest()).rstrip(b'=').decode()
    login_state = secrets.token_urlsafe(32)
    url = await client.authorization_url(state=login_state, nonce=state['nonce'], challenge=challenge)
    values = parse_qs(urlsplit(url).query)
    assert values['state'] == [login_state] and values['nonce'] == [state['nonce']]
    assert values['response_type'] == ['code'] and values['scope'] == ['openid']
    assert values['code_challenge'] == [challenge] and values['code_challenge_method'] == ['S256']
    verified = await client.exchange(code='valid-code', verifier=state['verifier'], nonce=state['nonce'])
    assert verified == {'iss': client.issuer, 'sub': 'external-subject'}
    assert state['requests'].count(('GET', '/.well-known/openid-configuration')) == 1
    assert state['requests'].count(('GET', '/keys')) == 1
    with pytest.raises(OidcProviderUnavailable):
        await client.exchange(code='valid-code', verifier=state['verifier'], nonce=state['nonce'])


@pytest.mark.asyncio
@pytest.mark.parametrize('fault', ['redirect', 'oversize', 'invalid_json', 'cross_origin', 'no_pkce', 'wrong_issuer'])
async def test_untrusted_metadata_and_unbounded_response_fail_closed(provider, fault):
    client, state, _ = provider; state['fault'] = fault
    with pytest.raises(OidcProviderUnavailable, match='^OIDC provider unavailable$'):
        await client.authorization_url(state=secrets.token_urlsafe(32), nonce=state['nonce'], challenge=secrets.token_urlsafe(32))
    assert all(path != '/redirect-target' for method, path in state['requests'])


@pytest.mark.asyncio
async def test_tls_certificate_must_be_trusted(provider):
    client, state, _ = provider
    untrusted = OidcProvider(client.issuer, 'fixture-client', client.redirect_uri)
    with pytest.raises(OidcProviderUnavailable):
        await untrusted.authorization_url(state=secrets.token_urlsafe(32), nonce=state['nonce'], challenge=secrets.token_urlsafe(32))
    with pytest.raises(ValueError):
        OidcProvider(client.issuer, 'fixture-client', client.redirect_uri, ssl_context=False)
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError):
        OidcProvider(client.issuer, 'fixture-client', client.redirect_uri, ssl_context=unverified)


@pytest.mark.asyncio
async def test_nonce_mismatch_does_not_return_identity(provider):
    client, state, _ = provider; state['fault'] = 'wrong_nonce'
    with pytest.raises(OidcTokenInvalid):
        await client.exchange(code='valid-code', verifier=state['verifier'], nonce=state['nonce'])


@pytest.mark.asyncio
async def test_unknown_kid_refreshes_only_trusted_keys(provider):
    client, state, _ = provider
    await client._load()
    state['key'] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    state['kid'] = 'rotated'
    assert (await client.exchange(code='valid-code', verifier=state['verifier'], nonce=state['nonce']))['sub'] == 'external-subject'
    assert state['requests'].count(('GET', '/keys')) == 2
    state['key'] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    state['kid'] = 'another-unrecognized-key'
    state['codes'].add('another-code')
    with pytest.raises(OidcTokenInvalid):
        await client.exchange(code='another-code', verifier=state['verifier'], nonce=state['nonce'])
    assert state['requests'].count(('GET', '/keys')) == 2


@pytest.mark.asyncio
async def test_confidential_client_uses_encoded_basic_auth(provider):
    client, state, ssl_context = provider
    state['client_secret'] = 'fixture:secret+value'
    confidential = OidcProvider(client.issuer, 'fixture-client', client.redirect_uri,
        client_secret=state['client_secret'], ssl_context=ssl_context)
    assert (await confidential.exchange(code='valid-code', verifier=state['verifier'], nonce=state['nonce']))['sub'] == 'external-subject'


@pytest.mark.asyncio
async def test_real_timeout_then_recovery(provider):
    client, state, _ = provider
    state['fault'] = 'slow'
    start = time.monotonic()
    with pytest.raises(OidcProviderUnavailable):
        await client.authorization_url(state=secrets.token_urlsafe(32), nonce=state['nonce'], challenge=secrets.token_urlsafe(32))
    assert time.monotonic() - start < 6.5
    state['fault'] = None
    url = await client.authorization_url(state=secrets.token_urlsafe(32), nonce=state['nonce'], challenge=secrets.token_urlsafe(32))
    assert url.startswith(client.issuer + '/authorize?')


@pytest.mark.asyncio
async def test_external_key_header_does_not_trigger_refresh(provider):
    client, state, _ = provider
    await client._load()
    state['kid'] = 'unknown'
    state['header_extra'] = {'jku': 'https://untrusted.example/keys'}
    with pytest.raises(OidcTokenInvalid):
        await client.exchange(code='valid-code', verifier=state['verifier'], nonce=state['nonce'])
    assert state['requests'].count(('GET', '/keys')) == 1
