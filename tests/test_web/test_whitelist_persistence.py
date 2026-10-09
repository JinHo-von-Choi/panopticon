from unittest.mock import MagicMock

import pytest
import yaml

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.detection.whitelist import Whitelist
from netwatcher.utils.yaml_editor import ConfigurationReadOnlyError
from netwatcher.web.routes.whitelist import create_whitelist_router
from netwatcher.utils.yaml_editor import YamlConfigEditor


@pytest.mark.parametrize("kind,value,normalized,key", [
    ("ip", "192.0.2.2", "192.0.2.2", "ips"),
    ("mac", "02:AA:00:00:00:91", "02:aa:00:00:00:91", "macs"),
    ("domain", "Backup.Example", "backup.example", "domains"),
    ("ip_range", "192.0.2.91/24", "192.0.2.0/24", "ip_ranges"),
    ("suffix", ".Office.Example", ".office.example", "domain_suffixes"),
])
def test_explicit_legacy_changes_preserve_intent_and_actual_file(tmp_path, kind, value, normalized, key):
    path = tmp_path / "config.yaml"
    path.write_text("netwatcher:\n  whitelist: {}\n")
    whitelist = Whitelist({})
    editor = YamlConfigEditor(str(path))
    app = FastAPI()
    app.include_router(create_whitelist_router(whitelist, editor), prefix="/api")
    client = TestClient(app)
    body = {"type":kind, "value":value, "present":True}
    for _ in range(2):
        response = client.post("/api/whitelist/toggle", json=body)
        assert response.status_code == 200
        assert response.json()["action"] == "added"
        assert whitelist.to_dict()[key].count(normalized) == 1
    assert yaml.safe_load(path.read_text())["netwatcher"]["whitelist"][key] == [normalized]
    for _ in range(2):
        response = client.post("/api/whitelist/toggle", json={**body, "present":False})
        assert response.status_code == 200
        assert response.json()["action"] == "removed"
        assert normalized not in whitelist.to_dict()[key]
    assert yaml.safe_load(path.read_text())["netwatcher"]["whitelist"][key] == []


@pytest.mark.parametrize("kind,value", [("ip_range","invalid/99"), ("suffix","example.com")])
def test_invalid_range_or_suffix_never_writes_configuration(kind, value):
    whitelist = Whitelist({})
    editor = MagicMock()
    app = FastAPI()
    app.include_router(create_whitelist_router(whitelist, editor), prefix="/api")
    response = TestClient(app).post("/api/whitelist/toggle", json={"type":kind,"value":value,"present":True})
    assert response.status_code == 400
    editor.update_whitelist_config.assert_not_called()


def test_failed_persistence_does_not_change_active_whitelist():
    whitelist = Whitelist({'ips': ['192.0.2.1']})
    editor = MagicMock()
    editor.update_whitelist_config.side_effect = ConfigurationReadOnlyError('read only')
    app = FastAPI()
    app.include_router(create_whitelist_router(whitelist, editor), prefix='/api')
    response = TestClient(app).post('/api/whitelist/toggle', json={'type': 'ip', 'value': '192.0.2.2'})
    assert response.status_code == 503
    assert whitelist.to_dict()['ips'] == ['192.0.2.1']


def test_confirmed_persistence_updates_same_active_whitelist():
    whitelist = Whitelist({})
    editor = MagicMock()
    app = FastAPI()
    app.include_router(create_whitelist_router(whitelist, editor), prefix='/api')
    response = TestClient(app).post('/api/whitelist/toggle', json={'type': 'ip', 'value': '192.0.2.2'})
    assert response.status_code == 200
    assert whitelist.is_ip_whitelisted('192.0.2.2')
    assert editor.update_whitelist_config.call_args.args[0]['ips'] == ['192.0.2.2']
