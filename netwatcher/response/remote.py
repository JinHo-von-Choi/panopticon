"""웹에서 사용하는 비동기 독립 실행기 클라이언트."""

from pathlib import Path

from netwatcher.response.command import ExecutionCommand
from netwatcher.response.lifecycle import LifecycleError
from netwatcher.response.transport import send_command


class RemoteExecutor:
    name = "shadow"
    applies_to_os = False
    kernel_expiry_verified = False

    def __init__(self, path: Path, *, expected_uid: int):
        if not path.is_absolute() or type(expected_uid) is not int or expected_uid < 0:
            raise ValueError("독립 실행기에는 절대 소켓 경로와 명시적 UID가 필요합니다")
        self.path = path
        self.expected_uid = expected_uid

    async def execute(self, command: ExecutionCommand):
        result = await send_command(self.path, command.to_bytes(), expected_uid=self.expected_uid)
        if (result.backend not in {"shadow", "executor"} or result.observed != "unknown"
                or result.outcome not in {"unverified", "error"}):
            raise LifecycleError("실행기 지원 상태와 결과가 일치하지 않습니다", 503)
        return result


def remote_client_from_config(config):
    settings = config.get("response_execution.remote", {})
    if not isinstance(settings, dict):
        raise ValueError("response_execution.remote must be a mapping")
    enabled = settings.get("enabled", False)
    if enabled is False:
        return None
    if enabled is not True:
        raise ValueError("response_execution.remote.enabled must be boolean")
    if config.get("response.enabled", False) not in (False, "false"):
        raise ValueError("독립 실행 연결과 기존 자동 차단을 함께 사용할 수 없습니다")
    if settings.get("backend", "shadow") != "shadow":
        raise ValueError("검증된 독립 OS 실행 연결이 아직 없습니다")
    path = settings.get("socket_path")
    if not isinstance(path, str) or not path:
        raise ValueError("독립 실행기 소켓 경로가 필요합니다")
    return RemoteExecutor(Path(path), expected_uid=settings.get("expected_uid"))


def configured_remote_executor(config, auth_manager, repository):
    client = remote_client_from_config(config)
    if client is None:
        return None
    if (auth_manager is None or not auth_manager.enabled or auth_manager.multi_user is not True
            or auth_manager.users is None or repository is None):
        raise ValueError("독립 실행 연결에는 관리형 인증과 조치 저장소가 필요합니다")
    return client
