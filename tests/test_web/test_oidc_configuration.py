"""명시적 OIDC 설정과 공급자 출처 제한을 확인한다."""

import pytest

from netwatcher.utils.config import Config
from netwatcher.web.oidc import OidcProvider
from netwatcher.web.oidc_login import configured_oidc_login


def test_default_oidc_is_disabled():
    assert configured_oidc_login(Config({}), None) is None


@pytest.mark.parametrize('settings', [None, [], 42, {'enabled': 1}, {'enabled': 'maybe'}])
def test_malformed_oidc_settings_fail_startup(settings):
    with pytest.raises(ValueError):
        configured_oidc_login(Config({'auth': {'oidc': settings}}), None)


@pytest.mark.parametrize('extra,reason', [
    ({'client_secret': 'fixture-secret'}, 'NETWATCHER_OIDC_CLIENT_SECRET'),
    ({'redirect_uri': 'https://console.example/other'}, 'redirect URI'),
    ({}, 'managed authentication')])
def test_oidc_requires_managed_auth_exact_callback_and_environment_secret(extra, reason, monkeypatch):
    monkeypatch.delenv('NETWATCHER_OIDC_CLIENT_SECRET', raising=False)
    settings = {'enabled': True, 'issuer': 'https://identity.example', 'client_id': 'fixture-client',
                'redirect_uri': 'https://console.example/api/auth/oidc/callback'} | extra
    with pytest.raises(ValueError, match=reason) as caught:
        configured_oidc_login(Config({'auth': {'oidc': settings}}), None)
    assert 'fixture-secret' not in str(caught.value)


def test_additional_endpoint_origins_are_explicit_and_bounded():
    provider = OidcProvider('https://identity.example/realm', 'fixture-client',
        'https://console.example/api/auth/oidc/callback', endpoint_origins=['https://keys.example'])
    assert provider._endpoint('https://keys.example:443/signing/keys') == 'https://keys.example:443/signing/keys'
    for value in ('http://keys.example/keys', 'https://other.example/keys', 'https://keys.example:444/keys'):
        with pytest.raises(ValueError):provider._endpoint(value)
    for values in (['https://keys.example/path'], ['http://keys.example'], ['https://keys.example'] * 9, 'https://keys.example'):
        with pytest.raises(ValueError):
            OidcProvider('https://identity.example', 'fixture-client',
                'https://console.example/api/auth/oidc/callback', endpoint_origins=values)
