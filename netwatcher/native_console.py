"""독립 센서의 저장 자료와 제어 소켓을 사용하는 일반 사용자 콘솔."""

import asyncio
import ctypes
import os
import signal
from pathlib import Path

from netwatcher.alerts.database_stream import DatabaseEventStream
from netwatcher.observability.sensor_health import SeparatedSensorHealthChecker
from netwatcher.replay.runs import ReplayRunService
from netwatcher.services.remote_sensor_control import RemoteSensorControl
from netwatcher.services.sensor_state import SensorObservationReader
from netwatcher.storage.database import Database
from netwatcher.storage.repositories import (DeviceRepository, EventRepository, IncidentRepository,
    ResponseActionRepository, ResponseProposalRepository, TrafficStatsRepository, ReplayRepository)
from netwatcher.storage.sensor_state import SensorStateRepository, StoredSensorObservation
from netwatcher.storage.user_accounts import UserAccounts
from netwatcher.support import enforce_support
from netwatcher.utils.logging_setup import setup_logging
from netwatcher.web.audit_log import AuditLogger
from netwatcher.web.auth import AuthManager
from netwatcher.web.server import create_app


def require_unprivileged_console():
    """root와 파일 capability를 통한 권한 획득을 허용하지 않는다."""
    if os.geteuid() == 0:
        raise ValueError("독립 콘솔은 일반 사용자로 실행해야 합니다")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if any(int(status[name].strip(), 16) != 0 for name in ("CapEff", "CapPrm", "CapAmb")):
        raise ValueError("독립 콘솔의 실행·허용·상속 capability는 없어야 합니다")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # Linux PR_SET_NO_NEW_PRIVS
        raise RuntimeError("독립 콘솔의 권한 획득 방지를 적용하지 못했습니다")


class NativeConsole:
    def __init__(self, config, *, database=None):
        if config.get("input.mode", "native") != "native":
            raise ValueError("독립 콘솔에는 input.mode: native가 필요합니다")
        if config.get("auth.enabled") not in (True, "true") or config.get("auth.multi_user") not in (True, "true"):
            raise ValueError("독립 콘솔에는 인증과 개인 계정 관리가 필요합니다")
        enforce_support(config)
        for path in ("response.enabled", "ha.enabled"):
            if config.get(path, False) not in (False, "false"):
                raise ValueError(f"독립 콘솔에서 {path}를 사용할 수 없습니다")
        if config.get("response_execution.enabled", False) not in (False, "false") and config.get("response_execution.remote.enabled") is not True:
            raise ValueError("독립 콘솔은 로컬 조치 실행기를 시작할 수 없습니다")
        control = config.get("native.control", {})
        if not isinstance(control, dict) or control.get("enabled") is not True:
            raise ValueError("독립 콘솔에는 활성화된 센서 제어 연결이 필요합니다")
        path = control.get("socket_path")
        if not isinstance(path, str) or not path:
            raise ValueError("독립 콘솔에는 센서 제어 소켓 경로가 필요합니다")
        self.config = config
        self.db = database or Database(config)
        self.accounts = UserAccounts(self.db)
        self.auth = AuthManager(config, users=self.accounts)
        if not self.auth.enabled or self.auth.multi_user is not True:
            raise ValueError("독립 콘솔에는 인증과 개인 계정 관리가 필요합니다")
        sensor_id = config.get("native.sensor_id")
        self.observation = StoredSensorObservation(SensorStateRepository(self.db), sensor_id)
        console = config.get("native.console", {})
        if not isinstance(console, dict):
            raise ValueError("native.console 설정이 유효하지 않습니다")
        self.reader = SensorObservationReader(self.observation, interval=console.get("refresh_seconds", 2))
        self.stream = DatabaseEventStream(self.db)
        self.control = RemoteSensorControl(self.db, sensor_id, Path(path), expected_uid=control.get("expected_uid"))
        self.health = SeparatedSensorHealthChecker(self.db, self.observation, self.stream, observation_reader=self.reader)
        self.replay = ReplayRunService(ReplayRepository(self.db),
            max_pending_runs=config.get('replay.max_pending_runs', 2),
            max_pending_bytes=config.get('replay.max_pending_bytes', 33554432),
            timeout=config.get('replay.timeout_seconds', 600))
        from netwatcher.services.maintenance import MaintenanceService
        self.maintenance = MaintenanceService(config, EventRepository(self.db), TrafficStatsRepository(self.db),
            IncidentRepository(self.db), None, None)
        self.app = None

    def build_app(self):
        self.app = create_app(self.config, EventRepository(self.db), DeviceRepository(self.db),
            TrafficStatsRepository(self.db), self.stream, auth_manager=self.auth,
            observation_service=self.observation, health_checker=self.health,
            sensor_control=self.control, incident_repository=IncidentRepository(self.db),
            response_repository=ResponseActionRepository(self.db),
            response_proposal_repo=ResponseProposalRepository(self.db),
            audit_logger=AuditLogger(self.db.pool), audit_required=True, replay_service=self.replay)
        return self.app

    async def run(self):
        import uvicorn
        from netwatcher.utils.i18n import i18n

        require_unprivileged_console()
        setup_logging(self.config)
        i18n.init(Path(__file__).parent / "web/static/locales", self.config.get("language.default", "ko"))
        try:
            await self.db.connect()
            app = self.build_app()
            tls = self.config.get("web.tls", {})
            ssl_args = {}
            if tls.get("enabled"):
                if not tls.get("certfile") or not tls.get("keyfile"):
                    raise ValueError("TLS 인증서와 개인키 경로가 필요합니다")
                ssl_args = {"ssl_certfile": tls["certfile"], "ssl_keyfile": tls["keyfile"]}
            server = uvicorn.Server(uvicorn.Config(app, host=self.config.get("web.host", "127.0.0.1"),
                port=self.config.get("web.port", 38585), log_level="warning", timeout_graceful_shutdown=5, **ssl_args))
            loop = asyncio.get_running_loop()
            previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                for sig in previous:
                    loop.add_signal_handler(sig, setattr, server, "should_exit", True)
                await self.reader.start()
                await self.stream.start()
                await self.maintenance.start()
                await server.serve()
            finally:
                for sig, handler in previous.items():
                    loop.remove_signal_handler(sig)
                    signal.signal(sig, handler)
        finally:
            self.replay.stop_accepting()
            try:
                await self.maintenance.stop()
                await self.stream.stop()
            finally:
                try:
                    await self.reader.stop()
                finally:
                    try:
                        await self.replay.stop()
                    finally:
                        await self.db.close()
