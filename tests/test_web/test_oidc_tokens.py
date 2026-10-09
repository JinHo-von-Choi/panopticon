"""실제 RSA 서명으로 OIDC 서명·수신자·nonce·시각 검증을 확인한다."""

import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from netwatcher.web.oidc import OidcTokenVerifier, OidcTokenInvalid

ISSUER = 'https://identity.example/tenant'
CLIENT = 'panopticon-fixture'
NONCE = 'fixture-nonce-32-characters-value'


@pytest.fixture(scope='module')
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(key, kid='test-key'):
    return json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {
        'kid': kid, 'alg': 'RS256', 'use': 'sig', 'key_ops': ['verify']}


def claims(**changes):
    now = int(time.time())
    return {'iss': ISSUER, 'sub': 'external-123', 'aud': CLIENT,
        'iat': now - 1, 'exp': now + 300, 'nonce': NONCE} | changes


def signed(key, payload=None, headers=None):
    return jwt.encode(payload or claims(), key, algorithm='RS256',
        headers={'kid': 'test-key'} | (headers or {}))


def verifier(key, **kwargs):
    return OidcTokenVerifier(ISSUER, CLIENT, {'keys': [public_jwk(key, **kwargs)]})


def test_valid_signed_token_preserves_exact_identity(signing_key):
    payload = verifier(signing_key).verify(signed(signing_key), nonce=NONCE)
    assert payload['iss'] == ISSUER and payload['sub'] == 'external-123'


@pytest.mark.parametrize('change', [
    {'iss': ISSUER + '/'}, {'iss': 'https://other.example'}, {'aud': 'other-client'},
    {'aud': []}, {'aud': [CLIENT, 'other']}, {'aud': [CLIENT, 'other'], 'azp': 'other'},
    {'azp': 'other'}, {'aud': [CLIENT, 1]}, {'sub': ''}, {'sub': '사용자'},
    {'nonce': 'other-nonce-value'}, {'nonce': '한글-nonce-value'}, {'nonce': True},
    {'exp': lambda: int(time.time()) - 30}, {'iat': lambda: int(time.time()) + 600},
    {'iat': '123'}, {'iat': True}, {'exp': '123'}, {'exp': True},
    {'nbf': lambda: int(time.time()) + 600}, {'auth_time': lambda: int(time.time()) + 600},
    {'auth_time': '123'}, {'at_hash': 'wrong'}, {'c_hash': 'wrong'}])
def test_wrong_claims_are_rejected(signing_key, change):
    current_change = {key: value() if callable(value) else value for key, value in change.items()}
    token = signed(signing_key, claims(**current_change))
    with pytest.raises(OidcTokenInvalid, match='^Invalid ID token$'):
        verifier(signing_key).verify(token, nonce=NONCE, access_token='access-value', code='code-value')


@pytest.mark.parametrize('missing', ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'])
def test_required_claim_cannot_be_missing(signing_key, missing):
    payload = claims(); payload.pop(missing)
    with pytest.raises(OidcTokenInvalid):
        verifier(signing_key).verify(signed(signing_key, payload), nonce=NONCE)


def test_multi_audience_requires_matching_authorized_party(signing_key):
    payload = claims(aud=[CLIENT, 'other'], azp=CLIENT)
    assert verifier(signing_key).verify(signed(signing_key, payload), nonce=NONCE)['azp'] == CLIENT


def test_token_and_code_hashes_are_bound_to_actual_exchange(signing_key):
    digest = lambda text: base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()[:16]).rstrip(b'=').decode()
    payload = claims(at_hash=digest('actual-access'), c_hash=digest('actual-code'))
    token = signed(signing_key, payload)
    checked = verifier(signing_key).verify(token, nonce=NONCE, access_token='actual-access', code='actual-code')
    assert checked['sub'] == 'external-123'
    for data in ({}, {'access_token': 'actual-access'},
                 {'access_token': 'wrong-access', 'code': 'actual-code'}):
        with pytest.raises(OidcTokenInvalid):
            verifier(signing_key).verify(token, nonce=NONCE, **data)


@pytest.mark.parametrize('headers', [{'kid': 'other-key'}, {'kid': []}, {'crit': ['custom']},
    {'jku': 'https://untrusted.example'}, {'x5u': 'https://untrusted.example'},
    {'jwk': {'kty': 'oct', 'k': 'secret'}}, {'b64': True}])
def test_header_cannot_choose_algorithm_or_external_keys(signing_key, headers):
    # PyJWT의 생성기는 b64 등 일부 헤더를 제거하므로 실제 입력 바이트를 서명한다.
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=')
    header = {'alg': 'RS256', 'kid': 'test-key'} | headers
    data = encode(json.dumps(header).encode()) + b'.' + encode(json.dumps(claims()).encode())
    signature = signing_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    token = (data + b'.' + encode(signature)).decode()
    with pytest.raises(OidcTokenInvalid):
        verifier(signing_key).verify(token, nonce=NONCE)


def test_unsigned_hmac_substitution_and_altered_payload_rejected(signing_key):
    check = verifier(signing_key)
    for token in (jwt.encode(claims(), '', algorithm='none'),
                  jwt.encode(claims(), 'attacker-secret', algorithm='HS256', headers={'kid': 'test-key'})):
        with pytest.raises(OidcTokenInvalid):
            check.verify(token, nonce=NONCE)
    token = signed(signing_key).split('.')
    token[1] = base64.urlsafe_b64encode(json.dumps(claims(sub='attacker')).encode()).rstrip(b'=').decode()
    with pytest.raises(OidcTokenInvalid):
        check.verify('.'.join(token), nonce=NONCE)


def test_different_signature_key_is_rejected(signing_key):
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(OidcTokenInvalid):
        verifier(signing_key).verify(signed(attacker), nonce=NONCE)


@pytest.mark.parametrize('value', ['a' * 16385, '', 'a.b.c', None,
    'W10.W10.invalid', '한글.token.signature'])
def test_malformed_and_oversize_tokens(signing_key, value):
    with pytest.raises(OidcTokenInvalid):
        verifier(signing_key).verify(value, nonce=NONCE)


def test_duplicate_claims_and_deep_json_are_rejected(signing_key):
    encoding = lambda value: base64.urlsafe_b64encode(value.encode()).rstrip(b'=').decode()
    header = encoding('{"alg":"RS256","kid":"test-key"}')
    for data in ('{"sub":"one","sub":"two"}', '[' * 1100 + '0' + ']' * 1100,
                 '{"iat":NaN}', 'null'):
        with pytest.raises(OidcTokenInvalid):
            verifier(signing_key).verify(header + '.' + encoding(data) + '.invalid', nonce=NONCE)


def test_private_weak_duplicate_and_ineligible_keys_rejected(signing_key):
    jwk = public_jwk(signing_key)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    for keys in ([], [jwk] * 33, [jwk, jwk], [jwk | {'d': 'private'}],
                 [jwk | {'key_ops': ['sign']}], [jwk | {'n': 'x' * 1501}],
                 [public_jwk(weak)], [jwk | {'alg': 'HS256'}],
                 [jwk | {'use': 'enc'}], [jwk | {'kid': 'line\nbreak'}]):
        with pytest.raises(ValueError):
            OidcTokenVerifier(ISSUER, CLIENT, {'keys': keys})


def test_rotated_key_requires_updated_trusted_key_set(signing_key):
    token = signed(signing_key, headers={'kid': 'rotated-key'})
    with pytest.raises(OidcTokenInvalid):
        verifier(signing_key).verify(token, nonce=NONCE)
    refreshed = OidcTokenVerifier(ISSUER, CLIENT, {'keys': [public_jwk(signing_key, 'rotated-key')]})
    assert refreshed.verify(token, nonce=NONCE)['sub'] == 'external-123'
