"""읽기 전용 EVE 콘솔이 패킷 소켓 초기화에 의존하지 않는다."""

from pathlib import Path
import subprocess
import sys


def test_eve_console_builds_when_capture_imports_are_forbidden(tmp_path):
    root = Path(__file__).resolve().parents[2]
    code = f"""
import importlib.abc
import secrets
import sys
from types import SimpleNamespace
sys.path.insert(0, {str(root)!r})

class RejectCapture(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == 'scapy' or fullname.startswith('scapy.') or fullname == 'netwatcher.capture' or fullname.startswith('netwatcher.capture.'):
            raise AssertionError('EVE imported a capture dependency: ' + fullname)

sys.meta_path.insert(0, RejectCapture())
from netwatcher.ingest.runtime import EveConsole
from netwatcher.utils.config import Config
config = Config({{'input': {{'mode': 'eve', 'eve': {{'sources': [{{
    'directory': {str(tmp_path)!r}, 'sensor_id': 'test', 'source_id': 'test'}}]}}}},
    'web': {{'host': '127.0.0.1'}}, 'auth': {{'jwt_secret': secrets.token_hex(32)}}}})
app = EveConsole(config, database=SimpleNamespace(pool=None)).build_app()
assert any(route.path == '/api/events' for route in app.routes)
assert any(route.path == '/api/input/status' for route in app.routes)
"""
    result = subprocess.run([sys.executable, "-I", "-c", code], cwd=root,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_remote_sensor_console_builds_when_capture_imports_are_forbidden(tmp_path):
    root = Path(__file__).resolve().parents[2]
    code = f"""
import importlib.abc
import secrets
import sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, {str(root)!r})
class RejectCapture(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == 'scapy' or fullname.startswith('scapy.') or fullname == 'netwatcher.capture' or fullname.startswith('netwatcher.capture.'):
            raise AssertionError('Remote console imported capture: ' + fullname)
sys.meta_path.insert(0, RejectCapture())
from netwatcher.alerts.stream import EventStream
from netwatcher.services.remote_sensor_control import RemoteSensorControl
from netwatcher.alerts.database_stream import DatabaseEventStream
from netwatcher.observability.sensor_health import SeparatedSensorHealthChecker
from netwatcher.native_console import NativeConsole
from netwatcher.services.sensor_state import SensorObservationReader
from netwatcher.storage.sensor_state import SensorStateRepository, StoredSensorObservation
from netwatcher.storage.repositories import EventRepository, DeviceRepository, TrafficStatsRepository, IncidentRepository
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.utils.config import Config
from netwatcher.web.auth import AuthManager
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.server import create_app
db=SimpleNamespace(pool=None)
config=Config({{'input':{{'mode':'native'}},'auth':{{'enabled':True,'multi_user':True,'jwt_secret':secrets.token_hex(32)}}}})
manager=AuthManager(config,users=UserAccounts(db))
control=RemoteSensorControl(db,'office',Path({str(tmp_path / 'sensor.sock')!r}),expected_uid=0)
stream=DatabaseEventStream(db)
observation=StoredSensorObservation(SensorStateRepository(db),'office')
reader=SensorObservationReader(observation)
assert reader.status()['status']=='unhealthy'
health=SeparatedSensorHealthChecker(db,observation,stream)
app=create_app(config,EventRepository(db),DeviceRepository(db),TrafficStatsRepository(db),stream,
    auth_manager=manager,audit_logger=AuditLogger(None),audit_required=True,sensor_control=control,
    observation_service=observation,health_checker=health,incident_repository=IncidentRepository(db))
assert any(route.path=='/api/engines' for route in app.routes)
assert any(route.path=='/api/incidents' for route in app.routes)
assert app.state.health_checker is health
assert observation.snapshot()['state']=='unknown'
"""
    result = subprocess.run([sys.executable, "-I", "-c", code], cwd=root,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
