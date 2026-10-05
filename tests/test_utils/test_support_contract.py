"""지원 프로필 계약 테스트 (PR 01).

원래 이 결함들은 "기능이 꺼져 있다"는 이유로 방치됐다. 여기서는 같은 결함이
조합되면 기동을 거부하는지 확인한다. 검증 통과가 enforcement 통과를 뜻하지
않는다는 점도 테스트 이름과 주석에 명시한다.
"""

from __future__ import annotations

import copy

import pytest

from netwatcher.support import (
    PROFILE_FULL,
    PROFILE_LIMITED,
    SupportContract,
    UnsupportedConfigurationError,
    enforce_support,
    validate_support,
)
from netwatcher.utils.config import Config


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """호스트 환경의 .env 값이 테스트를 오염시키지 않게 한다."""
    monkeypatch.delenv("NETWATCHER_SUPPORT_PROFILE", raising=False)
    monkeypatch.delenv("NETWATCHER_LOGIN_ENABLED", raising=False)
    monkeypatch.delenv("NETWATCHER_JWT_SECRET", raising=False)
    monkeypatch.delenv("NETWATCHER_LOGIN_PASSWORD", raising=False)


@pytest.fixture
def base_raw() -> dict:
    """모든 검사를 통과하는 최소 설정. 필요한 부분만 골라 mutate한다."""
    return {
        "support": {"profile": PROFILE_LIMITED},
        "web": {"host": "127.0.0.1", "cors": {"allowed_origins": ["http://localhost:38585"]}},
        "auth": {"enabled": True, "jwt_secret": "unit-test-secret", "token_expire_hours": 24},
        "postgresql": {"enabled": True, "port": 5432, "ssl_mode": "disable"},
        "response": {
            "enabled": True,
            "backend": "iptables",
            "chain_name": "NETWATCHER_BLOCK",
            "default_duration": 3600,
        },
        "ai_analyzer": {"enabled": True, "apply_mode": "propose"},
        "workers": 1,
        "ha": {"enabled": False},
    }


def _codes(contract: SupportContract) -> set[str]:
    return {v.code for v in contract.violations()}


# ------------------------------------------------------------------
# 기준 상태
# ------------------------------------------------------------------

def test_valid_configuration_passes(base_raw):
    assert validate_support(Config(base_raw)) == []


def test_passing_contract_is_not_enforcement_certification(base_raw):
    """계약 통과는 enforcement 통과가 아니다 (G0, PR 08)."""
    payload = SupportContract(Config(base_raw)).describe()
    assert payload["violations"] == []
    assert payload["enforcement_backends"] == ["iptables"]
    # nftables 는 미구현이므로 어떤 경우에도 enforcement 목록에 없다
    assert "nftables" not in payload["enforcement_backends"]


# ------------------------------------------------------------------
# 프로필
# ------------------------------------------------------------------

def test_unknown_profile_rejected(base_raw):
    base_raw["support"]["profile"] = "galactic"
    assert "SUP-000" in _codes(SupportContract(Config(base_raw)))


def test_profile_from_env(monkeypatch, base_raw):
    monkeypatch.setenv("NETWATCHER_SUPPORT_PROFILE", PROFILE_FULL)
    assert SupportContract(Config(base_raw)).profile == PROFILE_FULL


def test_limited_profile_rejects_multi_worker(base_raw):
    base_raw["workers"] = 4
    assert "SUP-050" in _codes(SupportContract(Config(base_raw)))


def test_full_profile_allows_multi_worker(base_raw):
    base_raw["support"]["profile"] = PROFILE_FULL
    base_raw["workers"] = 4
    assert "SUP-050" not in _codes(SupportContract(Config(base_raw)))


def test_limited_profile_rejects_ha(base_raw):
    base_raw["ha"]["enabled"] = True
    assert "SUP-051" in _codes(SupportContract(Config(base_raw)))


# ------------------------------------------------------------------
# enforcement 백엔드
# ------------------------------------------------------------------

@pytest.mark.parametrize("backend", ["nftables", "mock"])
def test_unimplemented_backend_rejected(base_raw, backend):
    base_raw["response"]["backend"] = backend
    assert _codes(SupportContract(Config(base_raw))) & {"SUP-001", "SUP-002"}


def test_nftables_rejected_even_in_full_profile(base_raw):
    """full 프로필도 미구현 enforcement 는 통과시키지 않는다."""
    base_raw["support"]["profile"] = PROFILE_FULL
    base_raw["response"]["backend"] = "nftables"
    assert "SUP-002" in _codes(SupportContract(Config(base_raw)))


def test_permanent_block_rejected(base_raw):
    base_raw["response"]["default_duration"] = 0
    assert "SUP-004" in _codes(SupportContract(Config(base_raw)))


def test_input_chain_rejected(base_raw):
    base_raw["response"]["chain_name"] = "INPUT"
    assert "SUP-005" in _codes(SupportContract(Config(base_raw)))


def test_disabled_response_skips_backend_checks(base_raw):
    base_raw["response"] = {"enabled": False, "backend": "nftables"}
    assert validate_support(Config(base_raw)) == []


# ------------------------------------------------------------------
# AI 쓰기 격리
# ------------------------------------------------------------------

def test_ai_apply_mode_rejected(base_raw):
    base_raw["ai_analyzer"]["apply_mode"] = "apply"
    assert "SUP-010" in _codes(SupportContract(Config(base_raw)))


def test_ai_disabled_skips_apply_mode_check(base_raw):
    base_raw["ai_analyzer"] = {"enabled": False, "apply_mode": "apply"}
    assert "SUP-010" not in _codes(SupportContract(Config(base_raw)))


# ------------------------------------------------------------------
# 인증 / 노출
# ------------------------------------------------------------------

def test_unauthenticated_external_bind_rejected(base_raw):
    base_raw["web"]["host"] = "0.0.0.0"
    base_raw["auth"]["enabled"] = False
    assert "SUP-020" in _codes(SupportContract(Config(base_raw)))


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_bind_without_auth_allowed(base_raw, host):
    base_raw["web"]["host"] = host
    base_raw["auth"]["enabled"] = False
    assert validate_support(Config(base_raw)) == []


def test_cors_wildcard_without_auth_rejected(base_raw):
    base_raw["web"]["host"] = "0.0.0.0"
    base_raw["web"]["cors"] = {"allowed_origins": ["*"]}
    base_raw["auth"]["enabled"] = False
    assert "SUP-021" in _codes(SupportContract(Config(base_raw)))


def test_missing_jwt_secret_rejected(base_raw):
    base_raw["auth"]["jwt_secret"] = ""
    assert "SUP-030" in _codes(SupportContract(Config(base_raw)))


def test_multi_user_rejected_until_role_claims_exist(base_raw):
    base_raw["auth"]["multi_user"] = True
    assert "SUP-032" in _codes(SupportContract(Config(base_raw)))


# ------------------------------------------------------------------
# 데이터베이스
# ------------------------------------------------------------------

def test_unsupported_ssl_mode_rejected(base_raw):
    base_raw["postgresql"]["ssl_mode"] = "sometimes"
    assert "SUP-040" in _codes(SupportContract(Config(base_raw)))


@pytest.mark.parametrize("port", [0, 70000, "not-a-port"])
def test_invalid_port_rejected(base_raw, port):
    base_raw["postgresql"]["port"] = port
    assert _codes(SupportContract(Config(base_raw))) & {"SUP-041", "SUP-042"}


# ------------------------------------------------------------------
# enforce / 에러
# ------------------------------------------------------------------

def test_enforce_raises_with_all_violations(base_raw):
    base_raw["response"]["backend"] = "nftables"
    base_raw["ai_analyzer"]["apply_mode"] = "apply"
    base_raw["web"]["host"] = "0.0.0.0"
    base_raw["auth"]["enabled"] = False

    with pytest.raises(UnsupportedConfigurationError) as exc:
        enforce_support(Config(base_raw))

    codes = {v.code for v in exc.value.violations}
    assert {"SUP-002", "SUP-010", "SUP-020"} <= codes
    assert "SUP-002" in str(exc.value)


def test_enforce_returns_contract_on_success(base_raw):
    contract = enforce_support(Config(base_raw))
    assert contract.profile == PROFILE_LIMITED


# ------------------------------------------------------------------
# 저장된 기본 설정 파일 자체가 계약을 만족하는지
# ------------------------------------------------------------------

def _shipped_config_path():
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
    if not path.exists():  # pragma: no cover - 저장소 배치에 의존
        pytest.skip("config/default.yaml not found")
    return path


def test_shipped_default_config_satisfies_contract(monkeypatch):
    """config/default.yaml 이 기동을 거부당하지 않는지 확인한다.

    로컬 .env 나 배포 환경변수에 기대지 않는다. 그 값이 있으면 같은 파일이
    사람마다 다른 판정을 받는다 — 그것은 판정이 아니다.
    """
    for var in (
        "NETWATCHER_LOGIN_ENABLED", "NETWATCHER_LOGIN_PASSWORD",
        "NETWATCHER_LOGIN_USERNAME", "NETWATCHER_JWT_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NETWATCHER_SKIP_DOTENV", "1")

    contract = SupportContract(Config.load(_shipped_config_path()))
    assert contract.violations() == [], (
        "기본 설정이 지원 계약을 위반한다:\n"
        + "\n".join(str(v) for v in contract.violations())
    )


def test_shipped_default_does_not_expose_unauthenticated_dashboard(monkeypatch):
    """기본 배포가 비밀번호 없는 대시보드를 LAN 전체에 열어두지 않는다.

    실제로 문제가 있었던 설정이다. `config/default.yaml` 은 0.0.0.0 + 인증 꺼짐
    으로 출고됐고, 로컬 .env 에 로그인 설정이 있는 개발자의 PC 에서만 게이트가
    통과했다. 배포 파일 자체는 자기 계약을 위반하고 있었다.
    """
    for var in ("NETWATCHER_LOGIN_ENABLED", "NETWATCHER_LOGIN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NETWATCHER_SKIP_DOTENV", "1")

    config = Config.load(_shipped_config_path())
    assert config.get("web.host") == "127.0.0.1", (
        "기본 web.host 가 루프백이 아니다 — SUP-020 을 만족하려면 인증까지 켜야 한다"
    )


def test_widening_web_host_without_auth_is_rejected(monkeypatch):
    """LAN 노출을 위해 host 를 넓히면 인증을 요구한다는 계약을 건다."""
    for var in ("NETWATCHER_LOGIN_ENABLED", "NETWATCHER_LOGIN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NETWATCHER_SKIP_DOTENV", "1")

    config = Config.load(_shipped_config_path())
    config._data["web"]["host"] = "0.0.0.0"

    codes = {v.code for v in SupportContract(config).violations()}
    assert "SUP-020" in codes, "인증 없이 LAN 노출을 막지 못했다"


def test_contract_does_not_mutate_config(base_raw):
    before = copy.deepcopy(base_raw)
    SupportContract(Config(base_raw)).violations()
    assert base_raw == before
