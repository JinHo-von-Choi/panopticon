"""소유 Unix 소켓에서 호출자 거절·손상된 프레임·응답 유실을 확인한다."""

import asyncio
import os
import socket
import stat
import struct
import sys
from pathlib import Path

import pytest

from netwatcher.response.executor import ExecutionResult
from netwatcher.response.lifecycle import LifecycleError
from netwatcher.response.transport import CommandServer, send_command
from tests.test_response.test_execution_command import message

pytestmark = [pytest.mark.asyncio, pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux peer credentials")]


async def test_socket_round_trip_and_permissions(tmp_path):
    calls = []

    async def handle(command):
        calls.append(command.action_id)
        return ExecutionResult("unverified", "unknown", detail="shadow", backend="shadow")

    path = tmp_path / "executor.sock"
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle)
    await server.start()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        result = await send_command(path, message(), expected_uid=os.getuid())
        assert result.observed == "unknown" and not result.verified
        assert calls == [1]
        with pytest.raises(ValueError):
            await server.start()
    finally:
        await server.close()
    assert not path.exists()


@pytest.mark.parametrize("wrong_side", ["server", "client"])
async def test_peer_uid_mismatch_never_calls_handler(tmp_path, wrong_side):
    calls = []

    async def handle(command):
        calls.append(command)
        return ExecutionResult("unverified", "unknown")

    path = tmp_path / "executor.sock"
    server = CommandServer(path, allowed_uid=os.getuid() + (wrong_side == "server"), handler=handle)
    await server.start()
    try:
        with pytest.raises(LifecycleError):
            await send_command(path, message(), expected_uid=os.getuid() + (wrong_side == "client"))
        await asyncio.sleep(0)
        assert calls == []
    finally:
        await server.close()


async def test_oversized_and_invalid_frames_do_not_execute(tmp_path):
    calls = []

    async def handle(command):
        calls.append(command)
        return ExecutionResult("unverified", "unknown")

    path = tmp_path / "executor.sock"
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle)
    await server.start()
    try:
        for payload in (struct.pack("!I", 8193), struct.pack("!I", 2) + b"[]"):
            reader, writer = await asyncio.open_unix_connection(str(path))
            writer.write(payload)
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 1) == b""
            writer.close()
            await writer.wait_closed()
        assert calls == []
    finally:
        await server.close()


async def test_response_loss_is_unknown_without_retry(tmp_path):
    calls = []

    async def handle(command):
        calls.append(command.action_id)
        raise ConnectionError("connection lost after execution")

    path = tmp_path / "executor.sock"
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle)
    await server.start()
    try:
        with pytest.raises(LifecycleError) as error:
            await send_command(path, message(), expected_uid=os.getuid())
        assert error.value.status_code == 503
        assert calls == [1]
    finally:
        await server.close()


async def test_existing_file_and_replaced_socket_are_preserved(tmp_path):
    async def handle(command):
        return ExecutionResult("unverified", "unknown")

    path = tmp_path / "executor.sock"
    path.write_text("existing")
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle)
    with pytest.raises(ValueError):
        await server.start()
    assert path.read_text() == "existing"
    path.unlink()
    await server.start()
    path.unlink()
    path.write_text("replacement")
    await server.close()
    assert path.read_text() == "replacement"


async def test_writable_directory_is_refused(tmp_path):
    async def handle(command):
        return ExecutionResult("unverified", "unknown")

    tmp_path.chmod(0o777)
    server = CommandServer(tmp_path / "executor.sock", allowed_uid=os.getuid(), handler=handle)
    with pytest.raises(ValueError):
        await server.start()


async def test_group_socket_keeps_peer_uid_check(tmp_path):
    async def handle(command):
        return ExecutionResult("unverified", "unknown")

    tmp_path.chmod(0o750)
    path = tmp_path / "group-executor.sock"
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle, socket_gid=os.getgid())
    await server.start()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o660
        assert path.stat().st_gid == os.getgid()
        assert (await send_command(path, message(), expected_uid=os.getuid())).observed == "unknown"
    finally:
        await server.close()


async def test_separate_process_uses_real_peer_credentials(tmp_path):
    script = '''
import asyncio, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
from netwatcher.response.transport import CommandServer
from netwatcher.response.executor import ExecutionResult
async def main():
    async def handle(command):
        return ExecutionResult("unverified", "unknown", detail=str(os.getpid()), backend="shadow")
    server = CommandServer(Path(sys.argv[1]), allowed_uid=os.getuid(), handler=handle)
    await server.start()
    print("ready", flush=True)
    try:
        await asyncio.to_thread(sys.stdin.buffer.readline)
    finally:
        await server.close()
asyncio.run(main())
'''
    path = tmp_path / "executor.sock"
    child = await asyncio.create_subprocess_exec(
        sys.executable, "-I", "-c", script, str(path), str(Path(__file__).resolve().parents[2]),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        assert await asyncio.wait_for(child.stdout.readline(), 5) == b"ready\n"
        result = await send_command(path, message(), expected_uid=os.getuid())
        assert result.detail == str(child.pid)
        assert child.pid != os.getpid()
        assert result.observed == "unknown" and not result.verified
    finally:
        child.stdin.close()
        try:
            await asyncio.wait_for(child.wait(), 5)
        except TimeoutError:
            child.kill()
            await child.wait()
    assert child.returncode == 0
    assert not path.exists()


@pytest.mark.parametrize("payload", [
    b'{"outcome":"confirmed","outcome":"unverified"}',
    b'[' * 2000 + b']' * 2000,
])
async def test_malformed_server_response_is_unconfirmed(tmp_path, payload):
    async def handle(reader, writer):
        size = struct.unpack("!I", await reader.readexactly(4))[0]
        await reader.readexactly(size)
        writer.write(struct.pack("!I", len(payload)) + payload)
        await writer.drain()
        writer.close()

    path = tmp_path / "bad-response.sock"
    server = await asyncio.start_unix_server(handle, path=str(path))
    try:
        with pytest.raises(LifecycleError) as error:
            await send_command(path, message(), expected_uid=os.getuid())
        assert error.value.status_code == 503
    finally:
        server.close()
        await server.wait_closed()


async def test_sigkill_socket_is_recovered_without_removing_live_server(tmp_path):
    path = tmp_path / 'executor.sock'
    code = '''
import asyncio,os,sys
from pathlib import Path
from netwatcher.response.transport import CommandServer
async def main():
    async def handle(command):
        raise RuntimeError('unexpected request')
    server=CommandServer(Path(sys.argv[1]),allowed_uid=os.getuid(),handler=handle)
    await server.start()
    print('ready',flush=True)
    await asyncio.Event().wait()
asyncio.run(main())
'''
    child = await asyncio.create_subprocess_exec(sys.executable, '-c', code, str(path),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    async def handle(command):
        return ExecutionResult('unverified', 'unknown', backend='shadow')
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle)
    try:
        assert await asyncio.wait_for(child.stdout.readline(), 5) == b'ready\n'
        before = path.stat().st_ino
        with pytest.raises(ValueError, match='already running'):
            await server.start()
        assert path.stat().st_ino == before
        child.kill()
        await child.wait()
        assert path.exists()
        await server.start()
        result = await send_command(path, message(), expected_uid=os.getuid())
        assert result.observed == 'unknown'
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()
        await server.close()
    assert not path.exists()


async def test_unrecorded_socket_and_unsafe_ownership_file_are_preserved(tmp_path):
    async def handle(command):
        return ExecutionResult('unverified', 'unknown')
    path = tmp_path / 'executor.sock'
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    foreign.bind(str(path))
    before = path.stat().st_ino
    server = CommandServer(path, allowed_uid=os.getuid(), handler=handle)
    try:
        with pytest.raises(ValueError, match='ownership is unconfirmed'):
            await server.start()
        assert path.stat().st_ino == before
    finally:
        foreign.close()
    path.unlink()
    lock = path.with_name(path.name + '.lock')
    lock.chmod(0o666)
    with pytest.raises(ValueError, match='owned and private'):
        await server.start()
    assert lock.stat().st_mode & 0o777 == 0o666
    lock.unlink()
    target = tmp_path / 'untouched'
    target.write_text('preserve')
    lock.symlink_to(target)
    with pytest.raises(OSError):
        await server.start()
    assert target.read_text() == 'preserve'
