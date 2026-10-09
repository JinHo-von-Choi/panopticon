"""Agent gateway contracts, credential boundaries and durable idempotency."""
import hashlib
import hmac
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager
from netwatcher.web.routes.agent_gateway import AgentGatewayStore, create_agent_gateway_router
from netwatcher.web.server import create_app


@pytest.fixture
def gateway(tmp_path):
    store = AgentGatewayStore(str(tmp_path / 'gateway.sqlite3'), 'test-enrollment-token')
    app = FastAPI()
    app.include_router(create_agent_gateway_router(store), prefix='/api')
    with TestClient(app) as client:
        yield client, store


def enroll(client, token='test-enrollment-token'):
    return client.post('/api/agent/enroll', json={
        'enrollment_token': token, 'hostname': 'host-1', 'platform': 'linux/x86_64',
    })


def signed(client, identity, route, payload, *, timestamp=None, token=None, signing_key=None):
    raw = json.dumps(payload, separators=(',', ':')).encode()
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    signature = hmac.new(bytes.fromhex(signing_key or identity['signing_key']), timestamp.encode() + b'\n' + raw, hashlib.sha256).hexdigest()
    return client.post('/api/agent/' + route, content=raw, headers={
        'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (token or identity['auth_token']),
        'X-Agent-UUID': identity['agent_uuid'], 'X-Agent-Timestamp': timestamp, 'X-Agent-Signature': signature,
    })


def heartbeat(identity):
    return {'agent_uuid': identity['agent_uuid'], 'latency_ms': 12.5, 'resources': {
        'load_1': 0.1, 'memory_total_bytes': 8192, 'memory_available_bytes': 4096, 'agent_rss_bytes': 2048,
    }}


def events(identity, seq=1):
    return {'agent_uuid': identity['agent_uuid'], 'seq': seq, 'events': [{
        'kind': 'connection', 'local_address': '127.0.0.1:3456', 'remote_address': '127.0.0.1:443',
        'state': '01', 'inode': 123, 'observed_at': int(time.time()),
    }]}


def test_enrollment_issues_distinct_credentials_and_consumes_token(gateway):
    client, store = gateway
    assert enroll(client, 'wrong').status_code == 401
    result = enroll(client)
    assert result.status_code == 201
    identity = result.json()
    assert str(uuid4()) != identity['agent_uuid']
    assert len(identity['signing_key']) == 64
    assert identity['auth_token'] != identity['signing_key']
    assert identity['heartbeat_interval_seconds'] == 5
    assert enroll(client).status_code == 401
    with store.connect() as db:
        row = db.execute('SELECT * FROM agents').fetchone()
        assert row['token_hash'] != identity['auth_token']
    assert (Path(store.database).stat().st_mode & 0o777) == 0o600


def test_disabled_enrollment_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv('PANOPTICON_ENROLLMENT_TOKEN', raising=False)
    app = FastAPI()
    app.include_router(create_agent_gateway_router(AgentGatewayStore(str(tmp_path / 'db'))), prefix='/api')
    assert enroll(TestClient(app)).status_code == 503


def test_expired_token(gateway):
    client, store = gateway
    digest = hashlib.sha256(store.enrollment_token.encode()).hexdigest()
    with store.connect() as db, db:
        db.execute('UPDATE enrollment_tokens SET expires_at=? WHERE digest=?', (time.time() - 1, digest))
    assert enroll(client).status_code == 401


def test_heartbeat_persists_resources_and_receive_time(gateway):
    client, store = gateway
    identity = enroll(client).json()
    before = time.time()
    assert signed(client, identity, 'heartbeat', heartbeat(identity)).status_code == 200
    with store.connect() as db:
        row = db.execute('SELECT * FROM agents').fetchone()
        assert row['last_seen'] >= before
        assert row['latency_ms'] == 12.5
        assert json.loads(row['resources'])['memory_available_bytes'] == 4096


@pytest.mark.parametrize('override', [{'token': 'wrong'}, {'signing_key': '00' * 32}, {'timestamp': 1}])
def test_invalid_credentials_and_stale_signatures(gateway, override):
    client, _ = gateway
    identity = enroll(client).json()
    assert signed(client, identity, 'heartbeat', heartbeat(identity), **override).status_code == 401


def test_identity_mismatch_and_unsigned_requests(gateway):
    client, _ = gateway
    identity = enroll(client).json()
    body = heartbeat(identity)
    assert client.post('/api/agent/heartbeat', json=body).status_code == 401
    body['agent_uuid'] = str(uuid4())
    assert signed(client, identity, 'heartbeat', body).status_code == 403


def test_events_retries_conflicts_gaps_and_anomalies(gateway):
    client, store = gateway
    identity = enroll(client).json()
    body = events(identity)
    first = signed(client, identity, 'events', body)
    assert first.status_code == 200 and first.json()['accepted'] == 1
    assert signed(client, identity, 'events', body).json()['duplicate'] is True
    body['events'][0]['state'] = 'closed'
    assert signed(client, identity, 'events', body).status_code == 409
    assert signed(client, identity, 'events', events(identity, 3)).status_code == 409
    anomaly = events(identity, 2)
    anomaly['events'][0].update(kind='anomaly', detail='unexpected remote endpoint')
    assert signed(client, identity, 'events', anomaly).status_code == 200
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM agent_events').fetchone()[0] == 2


def test_restart_preserves_auth_sequences_and_consumed_token(gateway):
    client, store = gateway
    identity = enroll(client).json()
    body = events(identity)
    assert signed(client, identity, 'events', body).status_code == 200
    app = FastAPI()
    app.include_router(create_agent_gateway_router(AgentGatewayStore(store.database, store.enrollment_token)), prefix='/api')
    with TestClient(app) as restarted:
        assert enroll(restarted).status_code == 401
        assert signed(restarted, identity, 'heartbeat', heartbeat(identity)).status_code == 200
        assert signed(restarted, identity, 'events', body).json()['duplicate'] is True


def test_concurrent_retries_accept_once(gateway):
    client, store = gateway
    identity = enroll(client).json()
    body = events(identity)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: signed(client, identity, 'events', body), range(4)))
    assert all(result.status_code == 200 for result in results)
    assert sum(result.json()['accepted'] for result in results) == 1


@pytest.mark.parametrize('seq', [0, -1, True, 1.5, 9223372036854775808])
def test_invalid_event_sequences(gateway, seq):
    client, _ = gateway
    identity = enroll(client).json()
    assert signed(client, identity, 'events', events(identity, seq)).status_code == 422


def test_agent_routes_work_with_dashboard_auth_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv('PANOPTICON_ENROLLMENT_TOKEN', 'test-enrollment-token')
    config = Config({'auth': {'enabled': True, 'password': 'test-password'},
                     'agent_gateway': {'database': str(tmp_path / 'gateway.sqlite3')}})
    auth = AuthManager(config)
    app = create_app(config, MagicMock(), MagicMock(), MagicMock(), MagicMock(), auth_manager=auth)
    with TestClient(app) as client:
        identity = enroll(client).json()
        assert signed(client, identity, 'heartbeat', heartbeat(identity)).status_code == 200
        assert client.get('/api/devices').status_code == 401
        assert client.get('/api/devices', headers={'Authorization': 'Bearer ' + identity['auth_token']}).status_code == 401
        assert client.post('/api/agent/heartbeat/extra').status_code == 401


def test_signature_covers_exact_body(gateway):
    client, _ = gateway
    identity = enroll(client).json()
    raw = json.dumps(heartbeat(identity)).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(bytes.fromhex(identity['signing_key']), timestamp.encode() + b'\n' + raw, hashlib.sha256).hexdigest()
    modified = raw.replace(b'12.5', b'99.5')
    assert client.post('/api/agent/heartbeat', content=modified, headers={
        'Content-Type': 'application/json', 'Authorization': 'Bearer ' + identity['auth_token'],
        'X-Agent-UUID': identity['agent_uuid'], 'X-Agent-Timestamp': timestamp, 'X-Agent-Signature': signature,
    }).status_code == 401


def test_concurrent_enrollment_consumes_once(gateway):
    client, _ = gateway
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: enroll(client).status_code, range(4)))
    assert sorted(results) == [201, 401, 401, 401]


def test_invalid_resources_and_oversized_batch(gateway):
    client, _ = gateway
    identity = enroll(client).json()
    body = heartbeat(identity)
    body['resources']['load_1'] = -1
    assert signed(client, identity, 'heartbeat', body).status_code == 422
    body = events(identity)
    body['events'] *= 257
    assert signed(client, identity, 'events', body).status_code == 422
