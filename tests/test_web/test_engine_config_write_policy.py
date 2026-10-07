"""엔진 설정 쓰기 경로의 거부 기반 검증 + 역할 분리 (PR 03).

이 테스트가 고정하는 것은 세 가지다.

1. 잘못된 값이 400 으로 거부되고 **런타임·YAML 어느 쪽에도 반영되지 않는다**
2. 유효한 값만 반영된다
3. 설정 쓰기는 ADMIN 역할을 요구한다 (권한 분리의 최소 단위: 읽기/제안/승인)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.web.routes.engines import create_engines_router
from netwatcher.web.rbac import Role

# 실제 엔진 스키마와 같은 형태
PORT_SCAN_SCHEMA = {
    "enabled": (bool, True),
    "window_seconds": {"type": int, "default": 60, "min": 1, "max": 3600},
    "threshold": {"type": int, "default": 50, "min": 1, "max": 1000},
    "cooldown_seconds": {"type": int, "default": 300, "min": 0, "max": 86400},
    "entropy_threshold": {"type": float, "default": 3.8, "min": 0.0, "max": 8.0},
}

EXISTING_CONFIG = {
    "enabled": True,
    "window_seconds": 60,
    "threshold": 50,
    "cooldown_seconds": 300,
    "entropy_threshold": 3.8,
}


def _make_registry(schema=PORT_SCAN_SCHEMA, config=None):
    registry = MagicMock()
    registry.get_engine_info.return_value = {
        "name": "port_scan",
        "enabled": True,
        "config": dict(EXISTING_CONFIG if config is None else config),
        "schema": [],
    }
    registry.get_engine_schema.return_value = schema
    registry.reload_engine.return_value = (True, None, [])
    return registry


@pytest.fixture
def registry():
    return _make_registry()


@pytest.fixture
def yaml_editor():
    return MagicMock()


@pytest.fixture
def client(registry, yaml_editor):
    app = FastAPI()
    app.include_router(create_engines_router(registry, yaml_editor), prefix="/api")
    return TestClient(app)


# ------------------------------------------------------------------
# 1. 거부: 반영되지 않아야 한다
# ------------------------------------------------------------------

@pytest.mark.parametrize(
    "body,expected_code",
    [
        ({"threshold": True}, "V-010"),              # bool → int 강제 변환 거부
        ({"threshold": "50"}, "V-010"),              # 문자열 → int 거부
        ({"threshold": 0}, "V-020"),                 # min 미만
        ({"threshold": 100000}, "V-021"),            # max 초과
        ({"window_seconds": 0}, "V-022"),            # 시간 파라미터 0
        ({"window_seconds": -5}, "V-022"),           # 시간 파라미터 음수
        ({"undeclared_key": 5}, "V-001"),            # 스키마 미선언 키
        ({"enabled": 1}, "V-010"),                   # int → bool 거부
    ],
)
def test_invalid_config_rejected_without_side_effects(client, registry, yaml_editor, body, expected_code):
    resp = client.put("/api/engines/port_scan/config", json=body)

    assert resp.status_code == 400, resp.text
    violations = resp.json()["violations"]
    assert any(v["code"] == expected_code for v in violations), violations

    # 핵심: 재로드도, YAML 기록도 일어나지 않는다
    registry.reload_engine.assert_not_called()
    yaml_editor.update_engine_config.assert_not_called()


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_literal_rejected(client, registry, yaml_editor, literal):
    """클라이언트가 JSON NaN/Infinity 리터럴을 보내도 거부한다.

    Python 의 json 은 기본적으로 NaN/Infinity 리터럴을 허용하므로,
    표면적으로 정상 JSON 인 것처럼 통과할 수 있다.
    """
    resp = client.put(
        "/api/engines/port_scan/config",
        content=f'{{"entropy_threshold": {literal}}}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400, resp.text
    assert any(v["code"] == "V-011" for v in resp.json()["violations"])
    registry.reload_engine.assert_not_called()
    yaml_editor.update_engine_config.assert_not_called()


def test_cumulative_limit_rejected(client, registry, yaml_editor):
    resp = client.put(
        "/api/engines/port_scan/config",
        json={"window_seconds": 3600, "cooldown_seconds": 86400},
    )
    assert resp.status_code == 400
    assert any(v["code"] == "V-031" for v in resp.json()["violations"])
    registry.reload_engine.assert_not_called()
    yaml_editor.update_engine_config.assert_not_called()


def test_merged_result_validated_against_schema(client, registry, yaml_editor):
    """기존 YAML 의 다른 필드가 스키마를 어기고 있으면 새 요청을 통과시키지 않는다."""
    registry.get_engine_info.return_value["config"] = dict(EXISTING_CONFIG)
    yaml_editor.get_engine_config.return_value = {
        **EXISTING_CONFIG, "window_seconds": 999999,
    }

    resp = client.put("/api/engines/port_scan/config", json={"threshold": 60})

    assert resp.status_code == 400
    assert "병합 결과" in resp.json()["error"]
    registry.reload_engine.assert_not_called()
    yaml_editor.update_engine_config.assert_not_called()


# ------------------------------------------------------------------
# 2. 허용
# ------------------------------------------------------------------

def test_valid_config_applied(client, registry, yaml_editor):
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)

    resp = client.put("/api/engines/port_scan/config", json={"threshold": 200})

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    merged = registry.reload_engine.call_args[0][1]
    assert merged["threshold"] == 200
    assert merged["window_seconds"] == 60
    yaml_editor.update_engine_config.assert_called_once_with("port_scan", {"threshold": 200})


def test_int_accepted_for_float_field(client, registry, yaml_editor):
    registry.get_engine_schema.return_value = {
        "enabled": (bool, True),
        "entropy_threshold": {"type": float, "default": 3.8, "min": 0.0, "max": 8.0},
    }
    yaml_editor.get_engine_config.return_value = {"enabled": True, "entropy_threshold": 3.8}

    resp = client.put("/api/engines/port_scan/config", json={"entropy_threshold": 4})

    assert resp.status_code == 200


def test_schema_absent_engine_keeps_previous_behavior(client, registry, yaml_editor):
    """스키마가 없는 엔진은 검증 대상이 아니다 (거부가 아니라 통과)."""
    registry.get_engine_schema.return_value = None
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)

    resp = client.put("/api/engines/port_scan/config", json={"anything": 1})

    assert resp.status_code == 200


def test_null_values_still_stripped(client, registry, yaml_editor):
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)

    resp = client.put("/api/engines/port_scan/config",
                      json={"threshold": 30, "window_seconds": None})

    assert resp.status_code == 200
    merged = registry.reload_engine.call_args[0][1]
    assert merged["window_seconds"] == 60


def test_reload_failure_still_skips_yaml(client, registry, yaml_editor):
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)
    registry.reload_engine.return_value = (False, "engine rejected", [])

    resp = client.put("/api/engines/port_scan/config", json={"threshold": 60})

    assert resp.status_code == 500
    yaml_editor.update_engine_config.assert_not_called()


# ------------------------------------------------------------------
# 3. 역할 분리
# ------------------------------------------------------------------

def test_toggle_requires_admin_role(registry, yaml_editor):
    app = FastAPI()
    app.include_router(create_engines_router(registry, yaml_editor), prefix="/api")

    from netwatcher.web.auth import AuthManager
    import time

    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = "test-secret"
    manager._expire_hours = 1
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    viewer_token = pyjwt.encode(
        {"sub": "v", "role": Role.VIEWER.value, "iat": now,
         "exp": now + timedelta(hours=1)},
        "test-secret", algorithm="HS256",
    )
    app.state.auth_manager = manager

    client = TestClient(app)
    resp = client.patch(
        "/api/engines/port_scan/toggle",
        json={"enabled": False},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403
    registry.disable_engine.assert_not_called()
    yaml_editor.update_engine_config.assert_not_called()


def test_config_write_requires_admin_role(registry, yaml_editor):
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone

    from netwatcher.web.auth import AuthManager

    app = FastAPI()
    app.include_router(create_engines_router(registry, yaml_editor), prefix="/api")

    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = "test-secret"
    manager._expire_hours = 1
    app.state.auth_manager = manager

    now = datetime.now(timezone.utc)
    analyst_token = pyjwt.encode(
        {"sub": "a", "role": Role.ANALYST.value, "iat": now,
         "exp": now + timedelta(hours=1)},
        "test-secret", algorithm="HS256",
    )
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)

    client = TestClient(app)
    resp = client.put(
        "/api/engines/port_scan/config",
        json={"threshold": 200},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert resp.status_code == 403
    registry.reload_engine.assert_not_called()


def test_admin_role_can_write(registry, yaml_editor):
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone

    from netwatcher.web.auth import AuthManager

    app = FastAPI()
    app.include_router(create_engines_router(registry, yaml_editor), prefix="/api")

    manager = AuthManager.__new__(AuthManager)
    manager._enabled = True
    manager._secret = "test-secret"
    manager._expire_hours = 1
    app.state.auth_manager = manager

    now = datetime.now(timezone.utc)
    admin_token = pyjwt.encode(
        {"sub": "a", "role": Role.ADMIN.value, "iat": now,
         "exp": now + timedelta(hours=1)},
        "test-secret", algorithm="HS256",
    )
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)

    client = TestClient(app)
    resp = client.put(
        "/api/engines/port_scan/config",
        json={"threshold": 200},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200


def test_read_endpoints_do_not_require_role(registry, yaml_editor):
    """읽기는 역할 제한 대상이 아니다."""
    app = FastAPI()
    app.include_router(create_engines_router(registry, yaml_editor), prefix="/api")
    client = TestClient(app)
    assert client.get("/api/engines").status_code == 200
    assert client.get("/api/engines/port_scan").status_code == 200


def test_read_only_config_does_not_reload_engine(client, registry, yaml_editor):
    from netwatcher.utils.yaml_editor import ConfigurationReadOnlyError
    yaml_editor.ensure_writable.side_effect = ConfigurationReadOnlyError('read only')
    response = client.put('/api/engines/port_scan/config', json={'threshold': 90})
    assert response.status_code == 503
    registry.reload_engine.assert_not_called()
    yaml_editor.update_engine_config.assert_not_called()


def test_failed_yaml_save_restores_previous_runtime_config(client, registry, yaml_editor):
    yaml_editor.get_engine_config.return_value = dict(EXISTING_CONFIG)
    yaml_editor.update_engine_config.side_effect = OSError('disk failure')
    response = client.put('/api/engines/port_scan/config', json={'threshold': 90})
    assert response.status_code == 503
    assert registry.reload_engine.call_count == 2
    assert registry.reload_engine.call_args.args == ('port_scan', EXISTING_CONFIG)
