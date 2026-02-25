"""Tests for engine configuration REST API.

작성자: 최진호
작성일: 2026-02-20
수정일: 2026-02-23
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.web.routes.engines import create_engines_router


@pytest.fixture
def mock_registry():
    """MagicMock EngineRegistry."""
    return MagicMock()


@pytest.fixture
def mock_yaml_editor():
    """MagicMock YamlConfigEditor."""
    return MagicMock()


@pytest.fixture
def client(mock_registry, mock_yaml_editor):
    """TestClient with engines router only."""
    app = FastAPI()
    app.include_router(
        create_engines_router(mock_registry, mock_yaml_editor),
        prefix="/api",
    )
    return TestClient(app)


# ------------------------------------------------------------------
# GET /api/engines
# ------------------------------------------------------------------

def test_list_engines(client, mock_registry):
    """GET /api/engines returns list of all engines."""
    mock_registry.get_all_engine_info.return_value = [
        {"name": "port_scan", "enabled": True, "config": {}, "schema": []},
        {"name": "dns_anomaly", "enabled": False, "config": {}, "schema": []},
    ]

    resp = client.get("/api/engines")

    assert resp.status_code == 200
    data = resp.json()
    assert "engines" in data
    assert len(data["engines"]) == 2
    assert data["engines"][0]["name"] == "port_scan"
    assert data["engines"][1]["name"] == "dns_anomaly"
    mock_registry.get_all_engine_info.assert_called_once()


# ------------------------------------------------------------------
# GET /api/engines/{name}
# ------------------------------------------------------------------

def test_get_engine_found(client, mock_registry):
    """GET /api/engines/port_scan returns engine detail."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan",
        "enabled": True,
        "config": {"threshold": 100},
        "schema": [],
    }

    resp = client.get("/api/engines/port_scan")

    assert resp.status_code == 200
    data = resp.json()
    assert data["engine"]["name"] == "port_scan"
    assert data["engine"]["enabled"] is True
    assert data["engine"]["config"]["threshold"] == 100
    mock_registry.get_engine_info.assert_called_once_with("port_scan")


def test_get_engine_not_found(client, mock_registry):
    """GET /api/engines/unknown returns 404."""
    mock_registry.get_engine_info.return_value = None

    resp = client.get("/api/engines/unknown_engine")

    assert resp.status_code == 404
    data = resp.json()
    assert "error" in data
    mock_registry.get_engine_info.assert_called_once_with("unknown_engine")


# ------------------------------------------------------------------
# PUT /api/engines/{name}/config
# ------------------------------------------------------------------

def test_update_config_success(client, mock_registry, mock_yaml_editor):
    """PUT /api/engines/{name}/config reloads then persists."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan",
        "enabled": True,
        "config": {"threshold": 100, "window": 60},
        "schema": [],
    }
    mock_yaml_editor.get_engine_config.return_value = {"threshold": 100, "window": 60}
    mock_yaml_editor.update_engine_config.return_value = None
    mock_registry.reload_engine.return_value = (True, None, [])

    body = {"threshold": 200}
    resp = client.put("/api/engines/port_scan/config", json=body)

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "engine" in data
    assert "warnings" not in data  # no warnings → key absent

    # Verify reload called BEFORE YAML persistence
    mock_registry.reload_engine.assert_called_once()
    call_args = mock_registry.reload_engine.call_args
    assert call_args[0][0] == "port_scan"
    merged = call_args[0][1]
    assert merged["threshold"] == 200
    assert merged["window"] == 60

    # YAML persistence called after successful reload
    mock_yaml_editor.update_engine_config.assert_called_once_with("port_scan", body)


def test_update_config_not_found(client, mock_registry, mock_yaml_editor):
    """PUT /api/engines/unknown/config returns 404."""
    mock_registry.get_engine_info.return_value = None

    resp = client.put("/api/engines/unknown_engine/config", json={"threshold": 50})

    assert resp.status_code == 404


def test_update_config_reload_fail_no_yaml_write(client, mock_registry, mock_yaml_editor):
    """PUT config: reload failure must NOT persist to YAML."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan", "enabled": True, "config": {}, "schema": [],
    }
    mock_yaml_editor.get_engine_config.return_value = {"threshold": 15}
    mock_registry.reload_engine.return_value = (False, "bad config", [])

    resp = client.put("/api/engines/port_scan/config", json={"threshold": -999})

    assert resp.status_code == 500
    assert "bad config" in resp.json()["error"]
    # YAML must NOT have been updated
    mock_yaml_editor.update_engine_config.assert_not_called()


def test_update_config_null_values_filtered(client, mock_registry, mock_yaml_editor):
    """PUT config: null values from empty form fields are stripped."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan", "enabled": True, "config": {}, "schema": [],
    }
    mock_yaml_editor.get_engine_config.return_value = {"threshold": 15, "window": 60}
    mock_registry.reload_engine.return_value = (True, None, [])

    body = {"threshold": 30, "window": None}  # window is null (empty input)
    resp = client.put("/api/engines/port_scan/config", json=body)

    assert resp.status_code == 200

    # reload_engine should receive merged without null window override
    merged = mock_registry.reload_engine.call_args[0][1]
    assert merged["threshold"] == 30
    assert merged["window"] == 60  # preserved from existing, not overwritten by null

    # YAML persistence should not include null key
    yaml_body = mock_yaml_editor.update_engine_config.call_args[0][1]
    assert "window" not in yaml_body


def test_update_config_returns_warnings(client, mock_registry, mock_yaml_editor):
    """PUT config: validation warnings included in response."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan", "enabled": True, "config": {}, "schema": [],
    }
    mock_yaml_editor.get_engine_config.return_value = {"threshold": 15}
    mock_registry.reload_engine.return_value = (
        True, None, ["port_scan.threshold: value 5000 is above maximum 1000"],
    )

    resp = client.put("/api/engines/port_scan/config", json={"threshold": 5000})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "warnings" in data
    assert len(data["warnings"]) == 1
    assert "above maximum" in data["warnings"][0]


# ------------------------------------------------------------------
# PATCH /api/engines/{name}/toggle
# ------------------------------------------------------------------

def test_toggle_disable(client, mock_registry, mock_yaml_editor):
    """PATCH /api/engines/{name}/toggle with enabled=false disables engine."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan",
        "enabled": True,
        "config": {},
        "schema": [],
    }
    mock_yaml_editor.update_engine_config.return_value = None
    mock_registry.disable_engine.return_value = (True, None, [])

    resp = client.patch("/api/engines/port_scan/toggle", json={"enabled": False})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["name"] == "port_scan"
    assert data["enabled"] is False

    mock_yaml_editor.update_engine_config.assert_called_once_with(
        "port_scan", {"enabled": False},
    )
    mock_registry.disable_engine.assert_called_once_with("port_scan")


def test_toggle_enable(client, mock_registry, mock_yaml_editor):
    """PATCH /api/engines/{name}/toggle with enabled=true enables engine."""
    mock_registry.get_engine_info.return_value = {
        "name": "port_scan",
        "enabled": False,
        "config": {"threshold": 100},
        "schema": [],
    }
    mock_yaml_editor.get_engine_config.return_value = {"threshold": 100, "enabled": True}
    mock_yaml_editor.update_engine_config.return_value = None
    mock_registry.enable_engine.return_value = (True, None, [])

    resp = client.patch("/api/engines/port_scan/toggle", json={"enabled": True})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["name"] == "port_scan"
    assert data["enabled"] is True

    mock_yaml_editor.update_engine_config.assert_called_once_with(
        "port_scan", {"enabled": True},
    )
    mock_registry.enable_engine.assert_called_once()
    call_args = mock_registry.enable_engine.call_args
    assert call_args[0][0] == "port_scan"
