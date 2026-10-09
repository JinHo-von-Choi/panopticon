"""Linux Unix 소켓의 제한된 조치 전송.

전송 계층은 호출 UID와 메시지 형식만 확인한다. 실행 핸들러는 독립 승인
조회·감사·중복 방지까지 완료한 뒤 백엔드를 호출해야 한다.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import socket
import stat
import struct
from collections.abc import Awaitable, Callable

from netwatcher.response.command import ExecutionCommand, MAX_COMMAND_BYTES
from netwatcher.response.executor import ExecutionResult
from netwatcher.response.lifecycle import LifecycleError
from netwatcher.response.socket_ownership import SocketOwnership

logger = logging.getLogger(__name__)

MAX_CONNECTIONS = 8
REQUEST_TIMEOUT_SECONDS = 5
RESULT_FIELDS = frozenset({"outcome", "observed", "rule_fingerprint", "detail", "backend", "verified"})


def _unique_result(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate result field")
        value[key] = item
    return value


def peer_uid(writer: asyncio.StreamWriter) -> int:
    connection = writer.get_extra_info("socket")
    if connection is None or not hasattr(socket, "SO_PEERCRED"):
        raise LifecycleError("실행기 호출 주체를 확인할 수 없습니다", 503)
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    return struct.unpack("3i", credentials)[1]


async def _read_frame(reader: asyncio.StreamReader) -> bytes:
    length = struct.unpack("!I", await reader.readexactly(4))[0]
    if not 0 < length <= MAX_COMMAND_BYTES:
        raise LifecycleError("실행기 메시지 크기가 허용 범위를 벗어났습니다", 409)
    return await reader.readexactly(length)


async def _write_frame(writer: asyncio.StreamWriter, payload: bytes, *, max_bytes: int = MAX_COMMAND_BYTES) -> None:
    if not 0 < len(payload) <= max_bytes:
        raise LifecycleError("실행기 응답 크기가 허용 범위를 벗어났습니다", 503)
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()


def _payload(result: ExecutionResult) -> bytes:
    return json.dumps(result.as_dict(), allow_nan=False, separators=(",", ":")).encode()


class CommandServer:
    """동시 연결·요청 시간·본문 크기를 제한하는 소켓 서버."""

    def __init__(self, path: Path, *, allowed_uid: int,
                 handler: Callable[[ExecutionCommand], Awaitable[ExecutionResult]],
                 socket_gid: int | None = None) -> None:
        if type(allowed_uid) is not int or allowed_uid < 0:
            raise ValueError("allowed_uid must be an explicit UID")
        if socket_gid is not None and (type(socket_gid) is not int or socket_gid < 0):
            raise ValueError("socket_gid must be an explicit GID")
        self.path = path
        self.allowed_uid = allowed_uid
        self.handler = handler
        self.socket_gid = socket_gid
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self._identity: tuple[int, int] | None = None
        self._ownership = SocketOwnership(path)

    async def start(self) -> None:
        # 전용 디렉터리에서 이전 프로세스의 소유가 확인된 소켓만 회수한다.
        parent = self.path.parent
        parent_stat = parent.lstat()
        if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid()
                or parent_stat.st_mode & 0o022 or parent.resolve() != parent):
            raise ValueError("socket directory must be owned, absolute and private")
        if self.socket_gid is not None and (parent_stat.st_gid != self.socket_gid or not parent_stat.st_mode & 0o010):
            raise ValueError("socket directory must allow the configured group to traverse")
        if self._server is not None:
            raise ValueError("socket path is already in use")
        # 미리 만든 소켓은 연결을 받기 전에 권한을 제한한다.
        self._ownership.acquire()
        listener = None
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.path))
            owned = self.path.lstat()
            self._identity = (owned.st_dev, owned.st_ino)
            if self.socket_gid is not None:
                os.chown(self.path, -1, self.socket_gid)
            os.chmod(self.path, 0o660 if self.socket_gid is not None else 0o600)
            self._ownership.record()
            listener.listen(MAX_CONNECTIONS)
            listener.setblocking(False)
            self._server = await asyncio.start_unix_server(self._accept, sock=listener,
                                                          limit=MAX_COMMAND_BYTES + 4)
        except BaseException:
            if listener is not None:
                listener.close()
            try:
                self._remove_owned_socket()
            finally:
                self._ownership.release()
            raise

    def _remove_owned_socket(self) -> None:
        try:
            current = self.path.lstat()
        except FileNotFoundError:
            return
        if self._identity == (current.st_dev, current.st_ino) and stat.S_ISSOCK(current.st_mode):
            self.path.unlink()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if len(self._tasks) >= MAX_CONNECTIONS:
            writer.close()
            return
        self._tasks.add(task)
        command = None
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                if peer_uid(writer) != self.allowed_uid:
                    raise LifecycleError("실행기 호출 권한이 없습니다", 403)
                command = ExecutionCommand.from_bytes(await _read_frame(reader))
                result = await self.handler(command)
                await _write_frame(writer, _payload(result))
        except LifecycleError as error:
            if command is not None:
                status = error.status_code if error.status_code in {400, 403, 409, 429, 503} else 503
                message = "실행 요청이 거절되었습니다" if status < 500 else "실행 결과를 확인할 수 없습니다. 상태 대조가 필요합니다"
                try:
                    async with asyncio.timeout(1):
                        await _write_frame(writer, json.dumps({"error": {"status": status, "message": message}}).encode())
                except (ConnectionError, TimeoutError) as exc:
                    logger.debug("Execution error reply failed (%s)", type(exc).__name__)
                    writer.close()
        except (ValueError, TypeError, asyncio.IncompleteReadError,
                ConnectionError, TimeoutError) as exc:
            logger.debug("Execution connection closed (%s)", type(exc).__name__)
            # 실행 후 연결이 끊겨도 다시 실행하지 않는다. 호출자는 상태를 대조한다.
            writer.close()
        finally:
            self._tasks.discard(task)
            writer.close()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        try:
            self._remove_owned_socket()
        finally:
            self._ownership.release()


async def send_command(path: Path, payload: bytes, *, expected_uid: int) -> ExecutionResult:
    """한 번만 전송한다. 응답 유실은 미확정으로 처리하고 재전송하지 않는다."""
    if type(expected_uid) is not int or expected_uid < 0:
        raise ValueError("expected_uid must be an explicit UID")
    ExecutionCommand.from_bytes(payload)
    writer = None
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            reader, writer = await asyncio.open_unix_connection(str(path), limit=MAX_COMMAND_BYTES + 4)
            if peer_uid(writer) != expected_uid:
                raise LifecycleError("실행기 소유자를 확인할 수 없습니다", 503)
            await _write_frame(writer, payload)
            value = json.loads(await _read_frame(reader), object_pairs_hook=_unique_result)
            if isinstance(value, dict) and set(value) == {"error"}:
                error = value["error"]
                if (not isinstance(error, dict) or set(error) != {"status", "message"}
                        or type(error["status"]) is not int or error["status"] not in {400, 403, 409, 429, 503}
                        or not isinstance(error["message"], str) or not 0 < len(error["message"]) <= 512):
                    raise ValueError("invalid execution error")
                raise LifecycleError(error["message"], error["status"])
            if not isinstance(value, dict) or set(value) != RESULT_FIELDS:
                raise ValueError("invalid execution result")
            if (value["outcome"] not in {"confirmed", "absent", "mismatch", "unverified", "error"}
                    or value["observed"] not in {"present", "absent", "unknown"}
                    or not isinstance(value["detail"], str) or not isinstance(value["backend"], str)
                    or (value["rule_fingerprint"] is not None and not isinstance(value["rule_fingerprint"], str))):
                raise ValueError("invalid result fields")
            result = ExecutionResult(value["outcome"], value["observed"], value["rule_fingerprint"],
                                     value["detail"], value["backend"])
            if value["verified"] is not result.verified:
                raise ValueError("inconsistent verification")
            return result
    except (OSError, ValueError, TypeError, RecursionError, asyncio.IncompleteReadError, TimeoutError):
        raise LifecycleError("실행 결과를 확인할 수 없습니다. 상태 대조가 필요합니다", 503) from None
    finally:
        if writer is not None:
            writer.close()
