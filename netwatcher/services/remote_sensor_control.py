"""웹이 센서의 현재 실행 세대에만 요청을 전달하도록 연결한다."""

import json
from pathlib import Path
from uuid import uuid4

from netwatcher.services.sensor_control import SensorControlError, SensorControlRequest
from netwatcher.services.sensor_control_transport import send_sensor_control
from netwatcher.storage.sensor_state import SensorStateRepository, _identity


class RemoteSensorControl:
    def __init__(self, db, sensor_id, path, *, expected_uid):
        _identity(sensor_id, uuid4())
        if not isinstance(path, Path) or not path.is_absolute() or type(expected_uid) is not int or expected_uid < 0:
            raise ValueError("센서 제어에는 절대 소켓 경로와 명시적인 센서 UID가 필요합니다")
        self.repository = SensorStateRepository(db)
        self.sensor_id, self.path, self.expected_uid = sensor_id, path, expected_uid

    async def _owner(self):
        try:
            state = await self.repository.read(self.sensor_id)
        except Exception:
            raise SensorControlError("sensor_state_unavailable", 503) from None
        if state is None or state["stale"]:
            raise SensorControlError("sensor_state_unavailable", 503)
        return str(state["owner"])

    async def _send(self, operation, engine, actor, *, owner=None, request_id=None, base="", updates=None):
        owner = owner or await self._owner()
        try:
            command = SensorControlRequest.from_bytes(json.dumps({"request_id": request_id or str(uuid4()),
                "sensor_id": self.sensor_id, "owner": owner, "actor_id": actor["uid"],
                "actor_version": actor["ver"], "operation": operation, "engine": engine,
                "base_version": base, "updates": updates or {}}, allow_nan=False).encode())
        except (KeyError, ValueError, TypeError, RecursionError):
            raise SensorControlError("sensor_request_invalid", 400) from None
        return await send_sensor_control(self.path, command.to_bytes(), expected_uid=self.expected_uid)

    async def read(self, engine, actor):
        return await self._send("engine.read", engine, actor)

    async def read_whitelist(self, actor):
        return await self._send("whitelist.read", "whitelist", actor)

    async def ai_status(self, actor):
        return await self._send("ai.status", "ai", actor)

    async def feed_health(self, actor):
        return await self._send("feeds.health", "feeds", actor)

    async def proposals(self, operation, actor, *, engine="proposals", request_id=None,
                        base_version="", updates=None):
        return await self._send(operation, engine, actor, request_id=request_id,
                                base=base_version, updates=updates)

    async def read_evidence(self, event_id, actor):
        return await self._send("evidence.read", "evidence", actor, updates={"event_id": event_id})

    async def evidence_chunk(self, event_id, actor, *, file_version, offset):
        return await self._send("evidence.chunk", "evidence", actor,
            updates={"event_id": event_id, "file_version": file_version, "offset": offset})

    async def pin_evidence(self, event_id, actor, *, request_id, base_version, updates):
        return await self._send("evidence.pin", "evidence", actor, request_id=request_id,
            base=base_version, updates={"event_id": event_id, **updates})

    async def read_rules(self, actor, *, limit=50, offset=0):
        return await self._send("rules.list", "rules", actor, updates={"limit": limit, "offset": offset})

    async def rule_entry(self, actor, *, rule_id):
        return await self._send("rules.entry", "rules", actor, updates={"rule_id": rule_id})

    async def change_rules(self, operation, actor, *, request_id, base_version, updates):
        return await self._send(operation, "rules", actor, request_id=request_id, base=base_version, updates=updates)

    async def read_blocklist(self, actor, *, entry_type=None, source=None, search=None, limit=50, offset=0):
        return await self._send("blocklist.list", "blocklist", actor, updates={"entry_type": entry_type,
            "source": source, "search": search, "limit": limit, "offset": offset})

    async def blocklist_stats(self, actor):
        return await self._send("blocklist.stats", "blocklist", actor)

    async def blocklist_entry(self, actor, *, entry_type, value):
        return await self._send("blocklist.entry", "blocklist", actor, updates={"type": entry_type, "value": value})

    async def set_blocklist(self, actor, *, request_id, base_version, updates):
        return await self._send("blocklist.set", "blocklist", actor, request_id=request_id,
                                base=base_version, updates=updates)

    async def set_whitelist(self, actor, *, request_id, base_version, updates):
        return await self._send("whitelist.set", "whitelist", actor, request_id=request_id,
                                base=base_version, updates=updates)

    async def list(self, actor):
        """모든 엔진 상태를 한 번의 센서 요청으로 가져온다.

        엔진마다 ``engine.read``를 따로 보내면 인증 쿼리·행 잠금·설정 파일
        파싱이 엔진 수만큼 반복되어 목록 1건에 수십 초가 걸렸다.

        조회는 읽기 전용이므로 실패해도 상태를 잃지 않는다. 그래서 일괄이
        거절되면(응답이 한계를 넘었거나, 이전 버전 센서가 연산을 모르는 경우)
        조용히 단건 경로로 되돌아간다. 콘솔이 센서보다 먼저 갱신되어
        세대만 어긋난 경우에도 목록은 계속 보인다.
        """
        owner = await self._owner()
        try:
            result = await self._send("engine.states", "states", actor, owner=owner)
        except SensorControlError:
            return await self._list_sequential(actor, owner)
        engines = [{**entry["engine"], "base_version": entry["base_version"]}
                   for entry in result["engines"]]
        return {"engines": engines, "control_process": "separate"}

    async def _list_sequential(self, actor, owner):
        """일괄 조회를 쓸 수 없을 때의 기존 단건 경로."""
        catalog = await self._send("engine.catalog", "catalog", actor, owner=owner)
        engines = []
        for name in catalog["engines"]:
            state = await self._send("engine.read", name, actor, owner=owner)
            engines.append({**state["engine"], "base_version": state["base_version"]})
        return {"engines": engines, "control_process": "separate"}

    async def change(self, operation, engine, actor, *, request_id, base_version, updates):
        return await self._send(operation, engine, actor, request_id=request_id, base=base_version, updates=updates)
