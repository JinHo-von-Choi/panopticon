"""실제 실행기 CLI의 독립 기동·DB 승인 대조·재기동·종료."""

import asyncio
from copy import deepcopy
import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest
import yaml

from netwatcher.response.runtime import ExecutionWorker
from netwatcher.response.transport import send_command
from netwatcher.utils.config import Config
from tests.test_response.test_execution_service import setup_action


def settings(tmp_path):
    return {"auth": {"enabled": True, "multi_user": True},
            "response_execution": {"worker": {"enabled": True, "backend": "shadow",
                "allowed_uid": os.getuid(), "socket_path": str(tmp_path / "executor.sock")}}}


@pytest.mark.parametrize("change", [
    {"enabled": False}, {"enabled": "true"}, {"backend": "nftables"},
    {"backend": "iptables"}, {"allowed_uid": None}, {"allowed_uid": True},
    {"allowed_uid": 0}, {"socket_path": "relative.sock"},
    {"protected_networks": "8.8.8.8"}, {"protected_networks": [1]},
    {"protected_networks": ["8.8.8.1/24"]}, {"socket_gid": True},
])
def test_invalid_worker_configuration_refuses_start(tmp_path, change):
    value = settings(tmp_path)
    value["response_execution"]["worker"].update(change)
    with pytest.raises(ValueError):
        ExecutionWorker(Config(value))


@pytest.mark.parametrize("auth", [{"enabled": False, "multi_user": True},
                                  {"enabled": True, "multi_user": False},
                                  {"enabled": 1, "multi_user": True}])
def test_worker_requires_managed_auth(tmp_path, auth):
    value = settings(tmp_path)
    value["auth"] = auth
    with pytest.raises(ValueError):
        ExecutionWorker(Config(value))


def test_import_does_not_load_console_or_capture():
    script = """import sys
from netwatcher.response.runtime import ExecutionWorker
assert 'netwatcher.app' not in sys.modules
assert 'netwatcher.web.server' not in sys.modules
assert not any(name == 'scapy' or name.startswith('scapy.') for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
                            capture_output=True, timeout=10)
    assert result.returncode == 0


@pytest.mark.asyncio
async def test_real_cli_executes_shadow_once_and_survives_restart(db, config, tmp_path):
    _, command, _ = await setup_action(db)
    value = deepcopy(config.raw)
    additions = settings(tmp_path)
    value["auth"] = additions["auth"]
    value["response_execution"] = additions["response_execution"]
    path = tmp_path / "worker.yaml"
    path.write_text(yaml.safe_dump({"netwatcher": value}, allow_unicode=True))
    path.chmod(0o600)
    log_path = tmp_path / "worker.log"
    log_path.touch(mode=0o600)
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith(("NETWATCHER_DB_", "NETWATCHER_LOGIN_")) or key == "PYTHONPATH":
            env.pop(key)
    env["NETWATCHER_SKIP_DOTENV"] = "1"
    socket_path = Path(additions["response_execution"]["worker"]["socket_path"])

    async def start(log):
        child = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "netwatcher", "--component", "executor", "-c", str(path),
            cwd=Path(__file__).resolve().parents[2], env=env, stdout=log, stderr=log)
        try:
            async with asyncio.timeout(10):
                while not socket_path.exists():
                    assert child.returncode is None, "worker stopped; inspect private worker.log"
                    await asyncio.sleep(0.02)
            return child
        except BaseException:
            if child.returncode is None:
                child.terminate()
            await child.wait()
            raise

    async def stop(child):
        child.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(child.wait(), 5)
        except TimeoutError:
            child.kill()
            await child.wait()
        assert child.returncode == 0
        assert not socket_path.exists()

    with log_path.open("ab") as log:
        child = await start(log)
        try:
            first = await send_command(socket_path, command.to_bytes(), expected_uid=os.getuid())
            assert first.backend == "shadow" and first.observed == "unknown" and not first.verified
        finally:
            await stop(child)
        child = await start(log)
        try:
            second = await send_command(socket_path, command.to_bytes(), expected_uid=os.getuid())
            assert first.as_dict() == second.as_dict()
        finally:
            await stop(child)
    assert await db.pool.fetchval("SELECT attempt_count FROM response_actions") == 1
    assert await db.pool.fetchval("SELECT count(*) FROM response_receipts") == 1
