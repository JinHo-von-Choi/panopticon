"""센서 설정 변경의 권한·세대·영속 중복 방지를 확인한다."""

import asyncio
from dataclasses import dataclass
import hashlib
import json
import math
import re
import yaml
from uuid import UUID, uuid4

from netwatcher.detection.validation import RESERVED_KEYS, validate_engine_config
from netwatcher.detection.schema_utils import normalize_schema
from netwatcher.storage.sensor_state import _identity
from netwatcher.web.change_audit import state_summary
from netwatcher.services.sensor_whitelist import candidate as whitelist_candidate, state as whitelist_state

MAX_REQUEST_BYTES = 8192
MAX_RESULT_BYTES = 65536
MAX_CLAIMS = 10000
READ_OPERATIONS = {"engine.catalog", "engine.read", "whitelist.read", "blocklist.list", "blocklist.stats", "blocklist.entry", "rules.list", "rules.entry", "evidence.read", "evidence.chunk", "feeds.health", "ai.status", "proposal.list", "proposal.entry"}


class SensorControlError(RuntimeError):
    def __init__(self, code, status=409):
        super().__init__(code)
        self.code, self.status = code, status


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("nonfinite value")


@dataclass(frozen=True)
class SensorControlRequest:
    request_id: str
    sensor_id: str
    owner: str
    actor_id: str
    actor_version: int
    operation: str
    engine: str
    base_version: str
    updates_json: bytes

    def to_bytes(self):
        value = {**self.__dict__, "updates": json.loads(self.updates_json)}
        del value["updates_json"]
        return _json(value)

    @classmethod
    def from_bytes(cls, payload):
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_REQUEST_BYTES:
            raise ValueError("invalid request length")
        value = json.loads(payload, object_pairs_hook=_unique, parse_constant=_reject_constant)
        fields = {"request_id", "sensor_id", "owner", "actor_id", "actor_version", "operation",
                  "engine", "base_version", "updates"}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError("invalid request fields")
        for key in ("request_id", "owner", "actor_id"):
            if not isinstance(value[key], str) or str(UUID(value[key])) != value[key]:
                raise ValueError("invalid identifier")
        _identity(value["sensor_id"], value["owner"])
        if type(value["actor_version"]) is not int or not 1 <= value["actor_version"] <= 2147483647:
            raise ValueError("invalid actor version")
        if value["operation"] not in READ_OPERATIONS | {"engine.configure", "engine.toggle", "whitelist.set", "blocklist.set", "rules.set", "rules.reload", "evidence.pin", "proposal.submit", "proposal.validate", "proposal.approve", "proposal.reject"}:
            raise ValueError("unsupported sensor operation")
        if not isinstance(value["engine"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value["engine"]):
            raise ValueError("invalid engine")
        if not isinstance(value["updates"], dict):
            raise ValueError("invalid engine updates")
        if value["operation"].startswith("whitelist.") and value["engine"] != "whitelist":
            raise ValueError("invalid whitelist resource")
        if value["operation"] == "ai.status" and value["engine"] != "ai":
            raise ValueError("invalid AI resource")
        if value["operation"] == "feeds.health" and value["engine"] != "feeds":
            raise ValueError("invalid feed resource")
        if value["operation"].startswith("blocklist."):
            from netwatcher.services.sensor_blocklist import validate_updates
            if value["engine"] != "blocklist":
                raise ValueError("invalid blocklist resource")
            validate_updates(value["operation"], value["updates"])
        if value["operation"].startswith("evidence."):
            from netwatcher.services.sensor_evidence import validate_updates
            if value["engine"] != "evidence":
                raise ValueError("invalid evidence resource")
            validate_updates(value["operation"], value["updates"])
        if value["operation"].startswith("rules."):
            from netwatcher.services.sensor_rules import validate_updates
            if value["engine"] != "rules":
                raise ValueError("invalid rules resource")
            validate_updates(value["operation"], value["updates"])
        if value["operation"].startswith("proposal."):
            from netwatcher.services.sensor_proposals import validate_updates
            if value["operation"] != "proposal.submit" and value["engine"] != "proposals":
                raise ValueError("invalid proposal resource")
            validate_updates(value["operation"], value["updates"])
        if value["operation"] in READ_OPERATIONS:
            if value["base_version"] != "" or (value["updates"] and not value["operation"].startswith(("blocklist.", "rules.", "evidence.", "proposal."))):
                raise ValueError("read operation cannot change configuration")
            if value["operation"] == "engine.catalog" and value["engine"] != "catalog":
                raise ValueError("invalid catalog request")
        elif not isinstance(value["base_version"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["base_version"]):
            raise ValueError("invalid base version")
        if value["operation"] == "engine.toggle" and (
                set(value["updates"]) != {"enabled"} or type(value["updates"]["enabled"]) is not bool):
            raise ValueError("invalid toggle")
        if value["operation"] == "whitelist.set":
            from netwatcher.services.sensor_whitelist import normalize_entry
            updates = value["updates"]
            if set(updates) != {"type", "value", "present"} or type(updates["present"]) is not bool:
                raise ValueError("invalid whitelist change")
            normalize_entry(updates["type"], updates["value"])
        return cls(**{key: value[key] for key in fields - {"updates"}}, updates_json=_json(value["updates"]))


class SensorControlService:
    def __init__(self, db, sensor_id, owner, registry, editor, on_unknown, *, feed_manager=None, pcap_writer=None, replay_service=None, ai_analyzer=None, flow_processor=None, worker_pool=None):
        _identity(sensor_id, owner)
        if not callable(on_unknown):
            raise ValueError("확인 불가 시 입력 중단 처리가 필요합니다")
        self.db, self.sensor_id, self.owner = db, sensor_id, UUID(str(owner))
        self.registry, self.editor, self.on_unknown = registry, editor, on_unknown
        self.flow_processor = flow_processor
        self.worker_pool = worker_pool if worker_pool is not None and worker_pool.is_multiprocess else None
        self.ai_analyzer = ai_analyzer
        from netwatcher.services.sensor_blocklist import SensorBlocklist
        self.blocklist = SensorBlocklist(feed_manager)
        self._blocklist_unconfirmed = False
        from netwatcher.services.sensor_rules import SensorRules
        self.rules = SensorRules(registry)
        self._rules_unconfirmed = False
        self._expected_rules = None
        self._rules_candidate = None
        from netwatcher.services.sensor_evidence import SensorEvidence
        self.evidence = SensorEvidence(pcap_writer)
        self._evidence_unconfirmed = False
        self._lock = asyncio.Lock()
        self._mutation_attempted = False
        self._generations = {}
        from netwatcher.services.sensor_proposals import SensorProposals
        self.proposals = SensorProposals(self, replay_service)

    async def _authorize(self, conn, request):
        if request.sensor_id != self.sensor_id or UUID(request.owner) != self.owner:
            raise SensorControlError("sensor_generation_changed")
        account = await conn.fetchrow("SELECT role,enabled,version FROM sensor_account_for_share($1::uuid)",
                                      UUID(request.actor_id))
        permitted = {"admin"}
        if request.operation in READ_OPERATIONS:
            permitted |= {"viewer", "analyst"}
        elif request.operation in {"proposal.submit", "proposal.validate"}:
            permitted.add("analyst")
        if (account is None or not account["enabled"] or account["version"] != request.actor_version
                or account["role"] not in permitted):
            raise SensorControlError("sensor_control_forbidden", 403)
        valid = await conn.fetchval("""SELECT NOT stopped AND owner=$2 AND lease_expires_at>clock_timestamp()
            FROM sensor_runtime_state WHERE sensor_id=$1 FOR UPDATE""", self.sensor_id, self.owner)
        if valid is not True:
            raise SensorControlError("sensor_generation_changed")

    def _engine_registry(self, name):
        if self.flow_processor is not None and self.flow_processor.get_engine_schema(name) is not None:
            return self.flow_processor
        return self.registry

    def _engine_config(self, name):
        if self.editor is None:
            return None
        if self._engine_registry(name) is self.flow_processor:
            return self.editor.get_flow_engine_config(name)
        return self.editor.get_engine_config(name)

    def _state(self, engine):
        info = self._engine_registry(engine).get_engine_info(engine)
        config = self._engine_config(engine)
        if info is None:
            raise SensorControlError("engine_not_found", 404)
        info = {**info, "configuration_available": config is not None}
        if not info["enabled"] and config is not None:
            info = {**info, "config": dict(config)}
        generation = self._generations.setdefault(engine, str(uuid4()))
        version = hashlib.sha256(_json({"owner": str(self.owner), "generation": generation,
                                       "configuration": config, "runtime": info})).hexdigest()
        return {"engine": info, "base_version": version}, config

    def _candidate(self, request, *, writable=True):
        if request.operation == "whitelist.set":
            before = self._whitelist_state()
            if before["base_version"] != request.base_version:
                raise SensorControlError("whitelist_configuration_changed")
            self.editor.ensure_writable()
            try:
                candidate = whitelist_candidate(self.registry.whitelist, json.loads(request.updates_json))
            except (ValueError, TypeError, UnicodeError):
                raise SensorControlError("whitelist_configuration_invalid", 400) from None
            return before, before["whitelist"], candidate.to_dict()
        state, previous = self._state(request.engine)
        if previous is None:
            raise SensorControlError("engine_configuration_unavailable", 503)
        if state["base_version"] != request.base_version:
            raise SensorControlError("engine_configuration_changed")
        if writable:
            self.editor.ensure_writable()
        updates = json.loads(request.updates_json)
        schema = self._engine_registry(request.engine).get_engine_schema(request.engine)
        if not isinstance(schema, dict):
            raise SensorControlError("engine_schema_unavailable", 503)
        defaults = {key: field["default"] for key, field in normalize_schema(schema).items()}
        merged = {**defaults, **previous, **updates}
        if not schema and set(updates) - RESERVED_KEYS:
            raise SensorControlError("engine_configuration_invalid", 400)
        if validate_engine_config(schema, updates, allow_partial=True) or validate_engine_config(schema, merged):
            raise SensorControlError("engine_configuration_invalid", 400)
        if "enabled" in merged and type(merged["enabled"]) is not bool:
            raise SensorControlError("engine_configuration_invalid", 400)
        if "tick_interval" in merged:
            interval = merged["tick_interval"]
            if (type(interval) not in (int, float) or interval <= 0
                    or type(interval) is float and not math.isfinite(interval)):
                raise SensorControlError("engine_configuration_invalid", 400)
        return state, previous, merged

    def _whitelist_state(self):
        if self.editor is None:
            raise SensorControlError("whitelist_configuration_unavailable", 503)
        try:
            from netwatcher.detection.whitelist import Whitelist
            from netwatcher.services.sensor_whitelist import KEYS
            persisted = self.editor.get_whitelist_config()
            for key in KEYS.values():
                entries = persisted.get(key, [])
                if not isinstance(entries, list) or any(not isinstance(value, str) or not 0 < len(value) <= 253 for value in entries):
                    raise ValueError("invalid persisted whitelist")
            if sum(len(persisted.get(key, [])) for key in KEYS.values()) > 1024:
                raise ValueError("persisted whitelist capacity exceeded")
            current = whitelist_state(self.registry.whitelist, self.owner,
                                      self._generations.setdefault("whitelist", str(uuid4())))
            if Whitelist(persisted).to_dict() != current["whitelist"]:
                raise SensorControlError("whitelist_configuration_changed")
            return current
        except (ValueError, TypeError):
            raise SensorControlError("whitelist_configuration_unavailable", 503) from None

    async def _blocklist_state(self, conn, request, *, updates=None, exact=False):
        if self._blocklist_unconfirmed:
            raise SensorControlError("blocklist_state_unconfirmed", 503)
        try:
            return await self.blocklist.state(conn, updates or json.loads(request.updates_json), self.owner,
                self._generations.setdefault("blocklist", str(uuid4())), exact=exact)
        except (ValueError, TypeError, UnicodeError):
            raise SensorControlError("blocklist_state_unavailable", 503) from None

    async def _mutation_candidate(self, conn, request):
        if self.proposals.unconfirmed:
            raise SensorControlError("proposal_state_unconfirmed", 503)
        if request.operation.startswith("proposal."):
            return await self.proposals.candidate(conn, request)
        if request.operation == "evidence.pin":
            evidence = await self._evidence_state(conn, request)
            if evidence["base_version"] != request.base_version:
                raise SensorControlError("evidence_configuration_changed")
            if evidence["state"] != "available" or evidence["pin_state"] == "unknown":
                raise SensorControlError("evidence_state_unavailable", 503)
            updates = json.loads(request.updates_json)
            try:
                await asyncio.to_thread(self.evidence.check_pin, updates)
            except FileNotFoundError:
                raise SensorControlError("evidence_file_unavailable", 404) from None
            except ValueError:
                raise SensorControlError("evidence_pin_capacity", 429) from None
            return evidence, evidence, {"event_id": updates["event_id"], "enabled": updates["enabled"],
                "hours": updates["hours"], "reason": updates["reason"]}
        if request.operation.startswith("rules."):
            state = await self._rules_state()
            if state["base_version"] != request.base_version:
                raise SensorControlError("rules_configuration_changed")
            try:
                after, engine, candidate = await asyncio.to_thread(self.rules.stage, request.operation, json.loads(request.updates_json))
            except KeyError:
                raise SensorControlError("rule_not_found" if request.operation == "rules.set" else "rules_candidate_invalid",
                                         404 if request.operation == "rules.set" else 400) from None
            except (ValueError, TypeError, OSError, yaml.YAMLError, re.error, AttributeError):
                raise SensorControlError("rules_candidate_invalid", 400) from None
            if self._expected_rules is not None:
                self._rules_candidate = (engine, candidate, request.operation)
            return state, {key: state[key] for key in ("rules_hash", "total")}, after
        if request.operation != "blocklist.set":
            return self._candidate(request)
        state = await self._blocklist_state(conn, request)
        if state["base_version"] != request.base_version:
            raise SensorControlError("blocklist_configuration_changed")
        updates = json.loads(request.updates_json)
        previous = state["entry"]
        after = {**previous, "present": updates["present"]}
        if not updates["present"]:
            after["notes_sha256"] = None
            after.update(notes="", notes_truncated=False, created_at=None)
        elif not previous["present"]:
            after["notes_sha256"] = hashlib.sha256(updates["notes"].encode()).hexdigest()
            after.update(notes=updates["notes"], notes_truncated=False)
        return state, previous, after

    async def _evidence_record(self, conn, request):
        if self._evidence_unconfirmed:
            raise SensorControlError("evidence_state_unconfirmed", 503)
        updates = json.loads(request.updates_json)
        row = await conn.fetchrow("SELECT metadata FROM events WHERE id=$1", updates["event_id"])
        if row is None:
            raise SensorControlError("event_not_found", 404)
        pcap = (row["metadata"] or {}).get("pcap", {})
        return pcap.get("sha256") if isinstance(pcap, dict) else None

    async def _evidence_state(self, conn, request):
        recorded_sha = await self._evidence_record(conn, request)
        try:
            state = await asyncio.to_thread(self.evidence.state, json.loads(request.updates_json)["event_id"],
                self.owner, self._generations.setdefault("evidence", str(uuid4())), recorded_sha)
            from netwatcher.services.sensor_evidence import validate_state
            validate_state(state, json.loads(request.updates_json)["event_id"])
            return state
        except (OSError, ValueError, TypeError, KeyError):
            raise SensorControlError("evidence_state_unavailable", 503) from None

    async def _read_evidence(self, conn, request):
        if request.operation == "evidence.read":
            result = {"status": "read", "request_id": request.request_id,
                      "evidence": await self._evidence_state(conn, request)}
        else:
            recorded_sha = await self._evidence_record(conn, request)
            try:
                chunk = await asyncio.to_thread(self.evidence.chunk, json.loads(request.updates_json), self.owner, recorded_sha)
            except FileNotFoundError:
                raise SensorControlError("evidence_file_unavailable", 404) from None
            except ValueError:
                raise SensorControlError("evidence_file_changed", 409) from None
            except OSError:
                raise SensorControlError("evidence_state_unavailable", 503) from None
            result = {"status": "read", "request_id": request.request_id, **chunk}
        from netwatcher.services.sensor_evidence import validate_result
        validate_result(request, result)
        return result

    async def _rules_state(self):
        if self._rules_unconfirmed:
            raise SensorControlError("rules_state_unconfirmed", 503)
        try:
            return await asyncio.to_thread(self.rules.state, self.owner,
                self._generations.setdefault("rules", str(uuid4())))
        except (ValueError, TypeError, KeyError, AttributeError):
            raise SensorControlError("rules_state_unavailable", 503) from None

    async def _read_rules(self, request):
        from netwatcher.services.sensor_rules import validate_result
        state = await self._rules_state()
        try:
            payload = self.rules.read(json.loads(request.updates_json))
        except KeyError:
            raise SensorControlError("rule_not_found", 404) from None
        result = {"status": "read", "request_id": request.request_id,
                  "base_version": state["base_version"], "rules_hash": state["rules_hash"], **payload}
        try:
            validate_result(request, result)
            if len(_json(result)) > 60000:
                raise ValueError("rule response too large")
        except (ValueError, TypeError):
            raise SensorControlError("rules_state_unavailable", 503) from None
        return result

    async def _read_blocklist(self, conn, request):
        if self._blocklist_unconfirmed:
            raise SensorControlError("blocklist_state_unconfirmed", 503)
        try:
            updates = json.loads(request.updates_json)
            if request.operation == "blocklist.list":
                state = self.blocklist.page(updates)
            elif request.operation == "blocklist.stats":
                state = {"stats": self.blocklist.stats()}
            else:
                state = await self._blocklist_state(conn, request)
            result = {"status": "read", "request_id": request.request_id, **state}
            from netwatcher.services.sensor_blocklist import validate_result
            validate_result(request, result)
            if len(_json(result)) > 60000:
                raise ValueError("blocklist response too large")
            return result
        except (ValueError, TypeError, UnicodeError):
            raise SensorControlError("blocklist_state_unavailable", 503) from None

    async def _audit(self, conn, request, action, details):
        await conn.execute("""INSERT INTO audit_log(user_id,action,resource,details) VALUES($1,$2,$3,$4)""",
            request.actor_id, action, "sensor/" + self.sensor_id + "/" + request.engine,
            {"request_id": request.request_id, "owner": request.owner, "engine": request.engine, **details})

    async def __call__(self, request):
        # 데이터클래스를 직접 만든 내부 호출도 전송 입력과 똑같이 검증한다.
        request = SensorControlRequest.from_bytes(request.to_bytes())
        async with self._lock:
            if request.operation in READ_OPERATIONS:
                async with self.db.pool.acquire() as conn, conn.transaction():
                    await self._authorize(conn, request)
                    if request.operation.startswith("proposal."):
                        result = await self.proposals.read(conn, request)
                        from netwatcher.services.sensor_proposals import validate_result
                        validate_result(request, result)
                        return result
                    if request.operation == "ai.status":
                        from netwatcher.services.sensor_ai import status
                        try:
                            value = status(self.ai_analyzer)
                        except (ValueError, TypeError, OverflowError, AttributeError):
                            raise SensorControlError("ai_state_unavailable", 503) from None
                        return {"status": "read", "request_id": request.request_id, "ai": value}
                    if request.operation == "feeds.health":
                        if self._blocklist_unconfirmed:
                            raise SensorControlError("feed_state_unconfirmed", 503)
                        from netwatcher.services.sensor_feeds import health
                        try:
                            value = health(self.blocklist.manager)
                        except (ValueError, TypeError, OverflowError):
                            raise SensorControlError("feed_state_unavailable", 503) from None
                        return {"status": "read", "request_id": request.request_id, "feeds": value}
                    if request.operation.startswith("blocklist."):
                        return await self._read_blocklist(conn, request)
                    if request.operation.startswith("rules."):
                        return await self._read_rules(request)
                    if request.operation.startswith("evidence."):
                        return await self._read_evidence(conn, request)
                    if request.operation == "whitelist.read":
                        return {"status": "read", "request_id": request.request_id, **self._whitelist_state()}
                    if request.operation == "engine.catalog":
                        names = [info["name"] for info in self.registry.get_all_engine_info()]
                        if self.flow_processor is not None:
                            names.extend(info["name"] for info in self.flow_processor.get_all_engine_info())
                        if len(names) > 64 or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) for name in names):
                            raise SensorControlError("engine_catalog_unavailable", 503)
                        return {"status": "catalog", "request_id": request.request_id, "engines": names}
                    state, _ = self._state(request.engine)
                    return {"status": "read", "request_id": request.request_id, **state}
            digest = hashlib.sha256(request.to_bytes()).hexdigest()
            async with self.db.pool.acquire() as conn, conn.transaction():
                await self._authorize(conn, request)
                row = await conn.fetchrow("SELECT * FROM sensor_control_claims WHERE request_id=$1 FOR UPDATE",
                                           UUID(request.request_id))
                if row is not None:
                    if row["command_hash"] != digest:
                        raise SensorControlError("sensor_request_conflict")
                    return row["result"] if row["status"] == "completed" else {
                        "status": "unknown", "request_id": request.request_id}
                archived = await conn.fetchval("SELECT archive_sensor_claims($1,$2,$3,$4)",
                    self.sensor_id, self.owner, UUID(request.request_id), MAX_CLAIMS)
                if archived:
                    raise SensorControlError("sensor_request_expired")
                before, previous, merged = await self._mutation_candidate(conn, request)
                await conn.execute("SELECT pg_advisory_xact_lock(178903421,4)")
                if await conn.fetchval("SELECT count(*) FROM sensor_control_claims") >= MAX_CLAIMS:
                    raise SensorControlError("sensor_control_capacity", 429)
                await conn.execute("""INSERT INTO sensor_control_claims(request_id,sensor_id,owner,actor_id,
                    command_hash) VALUES($1,$2,$3,$4,$5)""", UUID(request.request_id), self.sensor_id,
                    self.owner, UUID(request.actor_id), digest)
                await self._audit(conn, request, "sensor_change_prepared",
                                  {"before": state_summary(previous), "after": state_summary(merged)})
            # preparedを先に確定する。応答や完了記録を失っても同じ要求を再実行しない。
            self._mutation_attempted = False
            self._expected_rules = merged if request.operation.startswith("rules.") else None
            try:
                return await self._finish(request)
            except BaseException:
                if self._mutation_attempted:
                    if request.operation.startswith("proposal."):
                        self.proposals.unconfirmed = True
                    if request.operation == "blocklist.set":
                        self._blocklist_unconfirmed = True
                    if request.operation.startswith("rules."):
                        self._rules_unconfirmed = True
                    if request.operation == "evidence.pin":
                        self._evidence_unconfirmed = True
                    self.on_unknown()
                raise
            finally:
                self._mutation_attempted = False
                self._expected_rules = None
                self._rules_candidate = None

    async def _finish_rules(self, conn, request, before):
        from netwatcher.services.sensor_rules import validate_result
        self._mutation_attempted = True
        self.rules.apply(*self._rules_candidate)
        if self.worker_pool is not None:
            self.worker_pool.configure_rules(self.rules.engine().rules,
                reset_matcher=request.operation == "rules.reload")
        self._generations["rules"] = str(uuid4())
        state = await self._rules_state()
        payload = self.rules.read(json.loads(request.updates_json)) if request.operation == "rules.set" else {"total": state["total"]}
        result = {"status": "applied", "request_id": request.request_id,
                  "base_version": state["base_version"], "rules_hash": state["rules_hash"], **payload}
        validate_result(request, result)
        if len(_json(result)) > 60000:
            raise SensorControlError("sensor_result_too_large", 503)
        await self._audit(conn, request, "sensor_change_applied",
            {"before_version": before["base_version"], "after_version": state["base_version"]})
        await conn.execute("""UPDATE sensor_control_claims SET status='completed',result=$2,
            completed_at=clock_timestamp() WHERE request_id=$1""", UUID(request.request_id), result)
        return result

    async def _finish(self, request):
        async with self.db.pool.acquire() as conn, conn.transaction():
            await self._authorize(conn, request)
            await conn.fetchrow("SELECT request_id FROM sensor_control_claims WHERE request_id=$1 FOR UPDATE",
                                UUID(request.request_id))
            if request.operation.startswith("proposal."):
                return await self.proposals.finish(conn, request)
            before, previous, merged = await self._mutation_candidate(conn, request)
            if request.operation == "evidence.pin":
                updates = json.loads(request.updates_json)
                self._mutation_attempted = True
                try:
                    await asyncio.to_thread(self.evidence.pin, updates, request.actor_id, self.owner, before["file_version"])
                except FileNotFoundError:
                    raise SensorControlError("evidence_file_unavailable", 404) from None
                except ValueError:
                    raise SensorControlError("evidence_pin_unconfirmed", 503) from None
                self._generations["evidence"] = str(uuid4())
                evidence = await self._evidence_state(conn, request)
                result = {"status": "applied", "request_id": request.request_id, "evidence": evidence}
                from netwatcher.services.sensor_evidence import validate_result
                validate_result(request, result)
                await self._audit(conn, request, "sensor_change_applied",
                    {"before_version": before["base_version"], "after_version": evidence["base_version"]})
                await conn.execute("""UPDATE sensor_control_claims SET status='completed',result=$2,
                    completed_at=clock_timestamp() WHERE request_id=$1""", UUID(request.request_id), result)
                return result
            if request.operation.startswith("rules."):
                if merged != self._expected_rules:
                    raise SensorControlError("rules_candidate_changed")
                return await self._finish_rules(conn, request, before)
            if request.operation == "blocklist.set":
                updates = json.loads(request.updates_json)
                await self.blocklist.apply(conn, previous, updates)
                self._mutation_attempted = True
                self.blocklist.apply_memory(previous, updates["present"])
                if self.worker_pool is not None:
                    self.worker_pool.configure_feeds(self.blocklist.manager)
                self._generations["blocklist"] = str(uuid4())
                state = await self._blocklist_state(conn, request, updates=previous, exact=True)
                result = {"status": "applied", "request_id": request.request_id, **state}
                from netwatcher.services.sensor_blocklist import validate_result
                validate_result(request, result)
                await self._audit(conn, request, "sensor_change_applied",
                                  {"before_version": before["base_version"], "after_version": state["base_version"]})
                await conn.execute("""UPDATE sensor_control_claims SET status='completed',result=$2,
                    completed_at=clock_timestamp() WHERE request_id=$1""", UUID(request.request_id), result)
                return result
            if request.operation == "whitelist.set":
                from netwatcher.detection.whitelist import Whitelist
                candidate = Whitelist(merged)
                self._mutation_attempted = True
                self._generations[request.engine] = str(uuid4())
                self.editor.update_whitelist_config(merged)
                # 엔진이 참조하는 객체를 보존한다. 저장 실패 시 메모리를 바꾸지 않는다.
                self.registry.whitelist.__dict__.update(candidate.__dict__)
                if self.worker_pool is not None:
                    self.worker_pool.configure_whitelist(merged)
                state = self._whitelist_state()
                result = {"status": "applied", "request_id": request.request_id, **state}
                await self._audit(conn, request, "sensor_change_applied",
                                  {"before_version": before["base_version"], "after_version": state["base_version"]})
                await conn.execute("""UPDATE sensor_control_claims SET status='completed',result=$2,
                    completed_at=clock_timestamp() WHERE request_id=$1""", UUID(request.request_id), result)
                return result
            warnings = self._apply_engine(request, before, previous, merged)
            state, _ = self._state(request.engine)
            result = {"status": "applied", "request_id": request.request_id, **state,
                      "warnings": list(warnings)}
            if len(_json(result)) > 60000:
                raise SensorControlError("sensor_result_too_large", 503)
            await self._audit(conn, request, "sensor_change_applied",
                              {"before_version": before["base_version"], "after_version": state["base_version"]})
            await conn.execute("""UPDATE sensor_control_claims SET status='completed',result=$2,
                completed_at=clock_timestamp() WHERE request_id=$1""", UUID(request.request_id), result)
            return result

    def _apply_engine(self, request, before, previous, merged):
        """일반 설정 변경과 제안 승인이 같은 적용·복구 경로를 사용한다."""
        self.editor.ensure_writable()
        self._mutation_attempted = True
        self._generations[request.engine] = str(uuid4())
        if request.engine == "signature":
            self._generations["rules"] = str(uuid4())
        registry = self._engine_registry(request.engine)
        if merged.get("enabled", True) or registry is self.flow_processor:
            ok, error, warnings = registry.reload_engine(request.engine, merged)
        else:
            ok, error, warnings = registry.disable_engine(request.engine)
        if not ok:
            raise SensorControlError("engine_apply_failed", 503)
        if self.worker_pool is not None and registry is self.registry:
            self.worker_pool.configure_engine(request.engine, merged)
            if request.engine == "signature" and merged.get("enabled", True):
                self.worker_pool.configure_rules(self.rules.engine().rules)
        try:
            if registry is self.flow_processor:
                self.editor.update_flow_engine_config(request.engine, merged)
            else:
                self.editor.update_engine_config(request.engine, merged)
        except BaseException:
            if before["engine"]["enabled"]:
                registry.reload_engine(request.engine, previous)
            else:
                registry.disable_engine(request.engine)
            raise
        return list(warnings)
