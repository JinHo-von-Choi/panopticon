from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netwatcher.detection.whitelist import Whitelist
from netwatcher.utils.yaml_editor import ConfigurationReadOnlyError
from netwatcher.web.routes.whitelist import create_whitelist_router


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
