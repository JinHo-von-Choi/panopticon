"""Unix 소켓으로 제한된 엔진 설정 요청을 한 번만 전달한다."""

import asyncio
import json
import logging
import re
from pathlib import Path
import struct

from netwatcher.response.transport import (
    CommandServer, MAX_CONNECTIONS, REQUEST_TIMEOUT_SECONDS, peer_uid, _read_frame, _write_frame,
)
from netwatcher.services.sensor_control import (
    MAX_RESULT_BYTES, READ_OPERATIONS, SensorControlError, SensorControlRequest, _json, _unique, _reject_constant,
)

logger = logging.getLogger(__name__)


class SensorControlServer(CommandServer):
    """소켓 소유·권한·연결 수·정리 규칙은 기존 실행 전송과 공유한다."""

    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        if len(self._tasks) >= MAX_CONNECTIONS:
            writer.close()
            return
        self._tasks.add(task)
        request = None
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
                if peer_uid(writer) != self.allowed_uid:
                    raise SensorControlError("sensor_peer_forbidden", 403)
                request = SensorControlRequest.from_bytes(await _read_frame(reader))
                result = await self.handler(request)
                await _write_frame(writer, _json(result), max_bytes=MAX_RESULT_BYTES)
        except SensorControlError as exc:
            if request is not None:
                try:
                    async with asyncio.timeout(1):
                        await _write_frame(writer, _json({"error": {"code": exc.code, "status": exc.status}}))
                except (ConnectionError, TimeoutError):
                    writer.close()
        except (ValueError, TypeError, RecursionError, asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            writer.close()
        except Exception as exc:
            # 준비·반영 뒤의 저장 장애는 전송 성공으로 포장하지 않는다.
            logger.error("Sensor control result unconfirmed (%s)", type(exc).__name__)
            writer.close()
        finally:
            self._tasks.discard(task)
            writer.close()


async def send_sensor_control(path: Path, payload: bytes, *, expected_uid: int):
    request = SensorControlRequest.from_bytes(payload)
    if type(expected_uid) is not int or expected_uid < 0:
        raise ValueError("expected_uid must be explicit")
    writer = None
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_SECONDS):
            reader, writer = await asyncio.open_unix_connection(str(path), limit=MAX_RESULT_BYTES + 4)
            if peer_uid(writer) != expected_uid:
                raise SensorControlError("sensor_peer_unconfirmed", 503)
            await _write_frame(writer, payload)
            length = struct.unpack("!I", await reader.readexactly(4))[0]
            if not 0 < length <= MAX_RESULT_BYTES:
                raise ValueError("invalid result length")
            value = json.loads(await reader.readexactly(length), object_pairs_hook=_unique,
                               parse_constant=_reject_constant)
            if isinstance(value, dict) and set(value) == {"error"}:
                error = value["error"]
                if (not isinstance(error, dict) or set(error) != {"code", "status"}
                        or type(error["status"]) is not int or error["status"] not in {400,403,404,409,429,503}
                        or not isinstance(error["code"], str) or not 0 < len(error["code"]) <= 128):
                    raise ValueError("invalid error response")
                raise SensorControlError(error["code"], error["status"])
            if (not isinstance(value, dict) or value.get("request_id") != request.request_id
                    or value.get("status") not in {"catalog", "read", "applied", "unknown"}):
                raise ValueError("invalid sensor result")
            if value["status"] == "catalog":
                names = value.get("engines")
                if (request.operation != "engine.catalog" or set(value) != {"status", "request_id", "engines"}
                        or not isinstance(names, list) or len(names) > 64 or len(set(names)) != len(names)
                        or any(not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) for name in names)):
                    raise ValueError("invalid catalog")
            elif value["status"] == "unknown":
                if request.operation in READ_OPERATIONS or set(value) != {"status", "request_id"}:
                    raise ValueError("invalid unknown result")
            elif request.operation.startswith("proposal."):
                from netwatcher.services.sensor_proposals import validate_result
                validate_result(request, value)
            elif request.operation.startswith("blocklist."):
                from netwatcher.services.sensor_blocklist import validate_result
                validate_result(request, value)
            elif request.operation.startswith("rules."):
                from netwatcher.services.sensor_rules import validate_result
                validate_result(request, value)
            elif request.operation.startswith("evidence."):
                from netwatcher.services.sensor_evidence import validate_result
                validate_result(request, value)
            elif request.operation == "ai.status":
                from netwatcher.services.sensor_ai import validate_result
                validate_result(request, value)
            elif request.operation == "feeds.health":
                from netwatcher.services.sensor_feeds import validate_result
                validate_result(request, value)
            elif request.operation.startswith("whitelist."):
                from netwatcher.services.sensor_whitelist import KEYS
                entries = value.get("whitelist")
                if (set(value) != {"status", "request_id", "whitelist", "base_version"}
                        or (value["status"] == "read") != (request.operation == "whitelist.read")
                        or not isinstance(entries, dict) or set(entries) != set(KEYS.values())
                        or any(not isinstance(items, list) or any(not isinstance(item, str) or not 0 < len(item) <= 253 for item in items)
                               for items in entries.values())
                        or sum(len(items) for items in entries.values()) > 1024
                        or not isinstance(value["base_version"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["base_version"])):
                    raise ValueError("invalid whitelist result")
            else:
                fields = {"status", "request_id", "engine", "base_version"}
                if value["status"] == "applied":
                    fields.add("warnings")
                engine = value.get("engine")
                if (set(value) != fields or (value["status"] == "read") != (request.operation == "engine.read")
                        or not isinstance(engine, dict) or engine.get("name") != request.engine
                        or type(engine.get("enabled")) is not bool or not isinstance(engine.get("config"), dict)
                        or not isinstance(value["base_version"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["base_version"])):
                    raise ValueError("invalid applied configuration")
                if value["status"] == "applied" and (not isinstance(value["warnings"], list)
                        or len(value["warnings"]) > 64 or any(not isinstance(item, str) or len(item) > 512 for item in value["warnings"])):
                    raise ValueError("invalid warnings")
            return value
    except SensorControlError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, asyncio.IncompleteReadError, TimeoutError):
        raise SensorControlError("sensor_result_unknown", 503) from None
    finally:
        if writer is not None:
            writer.close()
