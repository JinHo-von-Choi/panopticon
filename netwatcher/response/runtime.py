"""캡처·웹 서버를 로드하지 않는 독립 실행기 프로세스."""

import asyncio
from pathlib import Path
import signal

from netwatcher.response.executor import ShadowExecutor
from netwatcher.response.service import ExecutionService
from netwatcher.response.transport import CommandServer
from netwatcher.storage.database import Database
from netwatcher.storage.execution_claims import ExecutionClaims
from netwatcher.utils.logging_setup import setup_logging


class ExecutionWorker:
    def __init__(self, config, *, database=None):
        settings = config.get("response_execution.worker", {})
        if not isinstance(settings, dict) or settings.get("enabled") is not True:
            raise ValueError("response_execution.worker.enabled must be true")
        if settings.get("backend", "shadow") != "shadow":
            raise ValueError("검증된 독립 OS 실행 백엔드가 아직 없습니다")
        enabled = config.get("auth.enabled", False)
        if not (enabled is True or enabled == "true") or config.get("auth.multi_user", False) is not True:
            raise ValueError("실행기에는 인증이 활성화된 다중 사용자 설정이 필요합니다")
        uid = settings.get("allowed_uid")
        if type(uid) is not int or uid <= 0:
            raise ValueError("실행기 호출자는 명시적인 일반 사용자 UID여야 합니다")
        socket_path = settings.get("socket_path")
        if not isinstance(socket_path, str) or not socket_path or not Path(socket_path).is_absolute():
            raise ValueError("실행기에는 절대 소켓 경로가 필요합니다")
        gid = settings.get("socket_gid")
        if gid is not None and (type(gid) is not int or gid < 0):
            raise ValueError("실행기 소켓 그룹에는 명시적인 GID가 필요합니다")
        protected = settings.get("protected_networks", [])
        if not isinstance(protected, list) or len(protected) > 128:
            raise ValueError("보호 경로 설정이 유효하지 않습니다")
        import ipaddress
        if any(not isinstance(item, str) for item in protected):
            raise ValueError("보호 경로는 CIDR 문자열이어야 합니다")
        for item in protected:
            ipaddress.ip_network(item, strict=True)
        self.config = config
        self.db = database or Database(config)
        service = ExecutionService(ExecutionClaims(self.db, protected=tuple(protected)), ShadowExecutor())
        self.server = CommandServer(Path(socket_path), allowed_uid=uid, handler=service,
                                    socket_gid=gid)

    async def run(self):
        setup_logging(self.config)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        installed = []
        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, stop.set)
                installed.append(sig)
            await self.db.connect()
            await self.server.start()
            await stop.wait()
        finally:
            await self.server.close()
            await self.db.close()
            for sig in installed:
                loop.remove_signal_handler(sig)
