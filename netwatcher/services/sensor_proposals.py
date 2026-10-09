"""센서 설정과 재생 근거에 묶인 제안 큐를 제한된 전송 형식으로 제공한다."""

from dataclasses import replace
from datetime import datetime
import hashlib
import json
import re
from uuid import UUID
from uuid import uuid4
from types import SimpleNamespace

from netwatcher.detection.proposal_validation import validate_pair, ValidationError
from netwatcher.services.sensor_control import SensorControlError, _json

READS = {"proposal.list", "proposal.entry"}
WRITES = {"proposal.submit", "proposal.validate", "proposal.approve", "proposal.reject"}
ANALYST_WRITES = {"proposal.submit", "proposal.validate"}
ROW_FIELDS = {"id", "engine", "params", "reason", "source", "before", "status", "applied",
              "apply_error", "validation_runs", "created_at", "decided_at", "decided_by", "decision_note",
              "sensor_id", "sensor_owner", "source_version"}


def positive(value):
    return type(value) is int and 1 <= value <= 9223372036854775807


def text(value, length):
    return isinstance(value, str) and len(value) <= length and "\x00" not in value


def validate_updates(operation, updates):
    fields = {
        "proposal.list": {"limit", "offset", "status"}, "proposal.entry": {"proposal_id"},
        "proposal.submit": {"params", "reason"},
        "proposal.validate": {"proposal_id", "normal_run_id", "attack_run_id"},
        "proposal.approve": {"proposal_id", "note"}, "proposal.reject": {"proposal_id", "note"},
    }
    if not isinstance(updates, dict) or set(updates) != fields.get(operation):
        raise ValueError("invalid proposal fields")
    if operation == "proposal.list":
        if (type(updates["limit"]) is not int or not 1 <= updates["limit"] <= 50
                or type(updates["offset"]) is not int or not 0 <= updates["offset"] <= 100000
                or updates["status"] not in {None, "pending", "approved", "rejected", "failed"}):
            raise ValueError("invalid proposal page")
    elif operation == "proposal.submit":
        if (not isinstance(updates["params"], dict) or not updates["params"]
                or not text(updates["reason"], 2000)):
            raise ValueError("invalid proposal submission")
    else:
        if not positive(updates["proposal_id"]):
            raise ValueError("invalid proposal identifier")
        if operation == "proposal.validate":
            if any(not positive(updates[key]) for key in ("normal_run_id", "attack_run_id")):
                raise ValueError("invalid replay identifier")
        elif operation in WRITES and not text(updates["note"], 1000):
            raise ValueError("invalid proposal note")


def row_payload(row):
    return {key: (value.isoformat() if isinstance(value, datetime) else str(value) if isinstance(value, UUID) else value)
            for key in ROW_FIELDS for value in [row.get(key)]}


def validate_row(row):
    if (not isinstance(row, dict) or set(row) != ROW_FIELDS or not positive(row["id"])
            or not isinstance(row["engine"], str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", row["engine"])
            or not isinstance(row["params"], dict) or not row["params"]
            or not isinstance(row["before"], dict) or not isinstance(row["validation_runs"], dict)
            or row["status"] not in {"pending", "approved", "rejected", "failed"}
            or row["source"] not in {"human", "ai"} or not text(row["reason"], 2000)
            or row["applied"] is not None and type(row["applied"]) is not bool
            or row["apply_error"] is not None and not text(row["apply_error"], 512)
            or row["decided_by"] is not None and not text(row["decided_by"], 100)
            or row["decision_note"] is not None and not text(row["decision_note"], 1000)):
        raise ValueError("invalid proposal row")
    from netwatcher.storage.sensor_state import _identity
    _identity(row["sensor_id"], row["sensor_owner"])
    if (str(UUID(row["sensor_owner"])) != row["sensor_owner"] or not isinstance(row["source_version"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", row["source_version"])):
        raise ValueError("invalid proposal origin")
    for key in ("created_at", "decided_at"):
        if row[key] is not None:
            if not text(row[key], 64):
                raise ValueError("invalid proposal timestamp")
            if datetime.fromisoformat(row[key]).tzinfo is None:
                raise ValueError("proposal timestamp has no timezone")
    if row["created_at"] is None:
        raise ValueError("missing proposal creation time")
    if (row["status"] == "pending" and (row["applied"] is not None or row["decided_at"] is not None)
            or row["status"] == "approved" and row["applied"] is not True
            or row["status"] == "rejected" and row["applied"] is not None
            or row["status"] == "failed" and row["applied"] is not False):
        raise ValueError("inconsistent proposal state")
    validation = row["validation_runs"]
    if validation:
        keys = {"normal_run_id", "attack_run_id", "build_version", "scope", "normal_input_hash",
                "attack_input_hash", "confirmed_by"}
        if (set(validation) != keys or any(not positive(validation[k]) for k in ("normal_run_id", "attack_run_id"))
                or validation["normal_run_id"] == validation["attack_run_id"]
                or validation["scope"] != "offline_feature_observations"
                or not text(validation["build_version"], 64) or not text(validation["confirmed_by"], 100)
                or any(not isinstance(validation[k], str) or not re.fullmatch(r"[a-f0-9]{64}", validation[k])
                       for k in ("normal_input_hash", "attack_input_hash"))):
            raise ValueError("invalid proposal validation")


def validate_result(request, result):
    updates = json.loads(request.updates_json)
    if request.operation == "proposal.list":
        if (set(result) != {"status", "request_id", "proposals", "validation_required", "total", "pending", "next_offset"}
                or result["status"] != "read" or not isinstance(result["proposals"], list)
                or len(result["proposals"]) > updates["limit"]
                or any(type(result[k]) is not int or result[k] < 0 for k in ("total", "pending"))
                or result["next_offset"] is not None and (type(result["next_offset"]) is not int
                    or result["next_offset"] != updates["offset"] + len(result["proposals"]))):
            raise ValueError("invalid proposal list")
        for row in result["proposals"]:
            validate_row(row)
            if row["sensor_id"] != request.sensor_id:
                raise ValueError("wrong proposal sensor")
            if updates["status"] is not None and row["status"] != updates["status"]:
                raise ValueError("wrong proposal status")
        if len({row["id"] for row in result["proposals"]}) != len(result["proposals"]):
            raise ValueError("duplicate proposal row")
    else:
        if set(result) != {"status", "request_id", "proposal", "base_version", "engine_state", "validation_required"}:
            raise ValueError("invalid proposal receipt")
        if result["status"] != ("read" if request.operation in READS else "applied"):
            raise ValueError("invalid proposal receipt status")
        row = result["proposal"]
        validate_row(row)
        if row["sensor_id"] != request.sensor_id:
            raise ValueError("wrong proposal sensor")
        if request.operation in {"proposal.submit", "proposal.validate", "proposal.approve"} and row["sensor_owner"] != request.owner:
            raise ValueError("wrong proposal generation")
        if request.operation == "proposal.submit" and row["source_version"] != request.base_version:
            raise ValueError("wrong proposal source version")
        if (request.operation == "proposal.submit" and row["engine"] != request.engine
                or request.operation != "proposal.submit" and row["id"] != updates["proposal_id"]
                or not isinstance(result["base_version"], str) or not re.fullmatch(r"[a-f0-9]{64}", result["base_version"])):
            raise ValueError("wrong proposal target")
        expected = {"proposal.submit": "pending", "proposal.validate": "pending",
                    "proposal.approve": "approved", "proposal.reject": "rejected"}.get(request.operation)
        if expected and row["status"] != expected:
            raise ValueError("wrong proposal decision")
        if request.operation == "proposal.approve" and row["applied"] is not True:
            raise ValueError("unapplied approval")
        if request.operation == "proposal.validate" and any(row["validation_runs"].get(k) != updates[k]
                for k in ("normal_run_id", "attack_run_id")):
            raise ValueError("wrong replay evidence")
        state = result["engine_state"]
        if state is not None and (not isinstance(state, dict) or set(state) != {"engine", "base_version"}
                or not isinstance(state["engine"], dict) or state["engine"].get("name") != row["engine"]
                or type(state["engine"].get("enabled")) is not bool or not isinstance(state["engine"].get("config"), dict)
                or not isinstance(state["base_version"], str) or not re.fullmatch(r"[a-f0-9]{64}", state["base_version"])):
            raise ValueError("invalid proposal engine state")
    if result["validation_required"] is not True or result["request_id"] != request.request_id:
        raise ValueError("invalid proposal validation policy")
    _json(result)


class SensorProposals:
    def __init__(self, control, replay):
        self.control, self.replay = control, replay
        self.unconfirmed = False

    async def submit_ai(self, engine, params, reason, expected_config):
        """센서 내부 분석은 제안 DB만 쓰며 관리자 실행 권한을 갖지 않는다."""
        from netwatcher.detection.proposals import ProposalError
        if not text(reason, 2000) or not isinstance(expected_config, dict):
            raise ProposalError("AI 제안 입력이 유효하지 않습니다")
        control = self.control
        async with control._lock:
            if self.unconfirmed:
                raise ProposalError("센서 제안 상태를 확인할 수 없습니다")
            try:
                state, previous = control._state(engine)
                if previous is None or previous != expected_config:
                    raise ProposalError("분석 이후 설정이 변경되었습니다")
                command = SimpleNamespace(operation="engine.configure", engine=engine,
                    base_version=state["base_version"], updates_json=_json(params))
                control._candidate(command, writable=False)
            except (SensorControlError, ValueError, TypeError, OverflowError):
                raise ProposalError("AI 제안 설정이 유효하지 않습니다") from None
            async with control.db.pool.acquire() as conn, conn.transaction():
                valid = await conn.fetchval("""SELECT NOT stopped AND owner=$2 AND lease_expires_at>clock_timestamp()
                    FROM sensor_runtime_state WHERE sensor_id=$1 FOR UPDATE""", control.sensor_id, control.owner)
                if valid is not True:
                    raise ProposalError("센서 실행 소유권을 확인할 수 없습니다")
                request_id = str(uuid4())
                details = {"request_id": request_id, "owner": str(control.owner), "engine": engine,
                           "source": "ai", "source_version": state["base_version"]}
                resource = "sensor/" + control.sensor_id + "/proposals"
                await conn.execute("INSERT INTO audit_log(user_id,action,resource,details) VALUES($1,$2,$3,$4)",
                    "sensor-ai", "sensor_ai_proposal_prepared", resource, details)
                pid = await conn.fetchval("""INSERT INTO config_proposals(engine,params,reason,source,before,sensor_id,sensor_owner,source_version)
                    VALUES($1,$2,$3,'ai',$4,$5,$6,$7) RETURNING id""", engine, params, reason,
                    previous, control.sensor_id, control.owner, state["base_version"])
                await conn.execute("INSERT INTO audit_log(user_id,action,resource,details) VALUES($1,$2,$3,$4)",
                    "sensor-ai", "sensor_ai_proposal_saved", resource, {**details, "proposal_id": pid})
                return pid

    async def entry(self, conn, request, proposal_id):
        row = await conn.fetchrow("SELECT * FROM config_proposals WHERE id=$1 AND sensor_id=$2 FOR UPDATE",
                                  proposal_id, self.control.sensor_id)
        if row is None:
            raise SensorControlError("proposal_not_found", 404)
        payload = row_payload(row)
        try:
            validate_row(payload)
            state, _ = self.control._state(row["engine"])
        except SensorControlError as error:
            if error.code != "engine_not_found":
                raise
            state = None
        except (ValueError, TypeError):
            raise SensorControlError("proposal_state_unavailable", 503) from None
        version = hashlib.sha256(_json({"owner": request.owner, "proposal": payload, "engine_state": state})).hexdigest()
        return {"status": "read", "request_id": request.request_id, "proposal": payload,
                "base_version": version, "engine_state": state, "validation_required": True}

    async def read(self, conn, request):
        if self.unconfirmed:
            raise SensorControlError("proposal_state_unconfirmed", 503)
        updates = json.loads(request.updates_json)
        if request.operation == "proposal.entry":
            return await self.entry(conn, request, updates["proposal_id"])
        total = await conn.fetchval("SELECT count(*) FROM config_proposals WHERE sensor_id=$2 AND ($1::text IS NULL OR status=$1)",
                                    updates["status"], self.control.sensor_id)
        pending = await conn.fetchval("SELECT count(*) FROM config_proposals WHERE status='pending' AND sensor_id=$1", self.control.sensor_id)
        rows = await conn.fetch("SELECT * FROM config_proposals WHERE sensor_id=$4 AND ($1::text IS NULL OR status=$1) ORDER BY created_at DESC,id DESC LIMIT $2 OFFSET $3",
                                updates["status"], updates["limit"], updates["offset"], self.control.sensor_id)
        result = {"status": "read", "request_id": request.request_id, "proposals": [],
                  "validation_required": True, "total": total, "pending": pending, "next_offset": None}
        for row in rows:
            payload = row_payload(row)
            validate_row(payload)
            result["proposals"].append(payload)
            if len(_json(result)) > 59000:
                result["proposals"].pop()
                break
        if rows and not result["proposals"]:
            raise SensorControlError("proposal_result_too_large", 503)
        next_offset = updates["offset"] + len(result["proposals"])
        if next_offset < total:
            result["next_offset"] = next_offset
        return result

    def engine_candidate(self, request, engine, base, params):
        command = replace(request, operation="engine.configure", engine=engine,
                          base_version=base, updates_json=_json(params))
        return command, self.control._candidate(command, writable=request.operation == "proposal.approve")

    async def candidate(self, conn, request):
        if self.unconfirmed:
            raise SensorControlError("proposal_state_unconfirmed", 503)
        updates = json.loads(request.updates_json)
        if request.operation == "proposal.submit":
            _, values = self.engine_candidate(request, request.engine, request.base_version, updates["params"])
            return values
        state = await self.entry(conn, request, updates["proposal_id"])
        if state["base_version"] != request.base_version:
            raise SensorControlError("proposal_changed")
        row = state["proposal"]
        if row["status"] != "pending":
            raise SensorControlError("proposal_already_decided")
        if request.operation == "proposal.reject":
            return state, row, {"status": "rejected", "note": updates["note"]}
        if row["sensor_owner"] != request.owner:
            raise SensorControlError("proposal_generation_changed")
        engine_state = state["engine_state"]
        if engine_state is None:
            raise SensorControlError("proposal_engine_unavailable", 503)
        if engine_state["base_version"] != row["source_version"]:
            raise SensorControlError("proposal_configuration_changed")
        command, values = self.engine_candidate(request, row["engine"], engine_state["base_version"], row["params"])
        if values[1] != row["before"]:
            raise SensorControlError("proposal_configuration_changed")
        if self.replay is None:
            raise SensorControlError("proposal_validation_unavailable", 503)
        runs = updates if request.operation == "proposal.validate" else row["validation_runs"]
        if not runs.get("normal_run_id") or not runs.get("attack_run_id"):
            raise SensorControlError("proposal_validation_required", 400)
        try:
            validation = await validate_pair(self.replay, row, runs["normal_run_id"], runs["attack_run_id"])
        except ValidationError:
            raise SensorControlError("proposal_validation_invalid", 400) from None
        validation["confirmed_by"] = request.actor_id if request.operation == "proposal.validate" else row["validation_runs"]["confirmed_by"]
        return state, row, {"validation": validation, "command": command.to_bytes().decode(), "candidate": values[2]}

    async def finish(self, conn, request):
        before, previous, candidate = await self.candidate(conn, request)
        updates = json.loads(request.updates_json)
        if request.operation == "proposal.submit":
            pid = await conn.fetchval("""INSERT INTO config_proposals(engine,params,reason,source,before,sensor_id,sensor_owner,source_version)
                VALUES($1,$2,$3,'human',$4,$5,$6,$7) RETURNING id""", request.engine, updates["params"], updates["reason"],
                previous, request.sensor_id, UUID(request.owner), request.base_version)
        else:
            pid = updates["proposal_id"]
            if request.operation == "proposal.validate":
                await conn.execute("UPDATE config_proposals SET validation_runs=$2 WHERE id=$1", pid, candidate["validation"])
            elif request.operation == "proposal.reject":
                await conn.execute("""UPDATE config_proposals SET status='rejected',decided_by=$2,
                    decision_note=$3,decided_at=clock_timestamp() WHERE id=$1""", pid, request.actor_id, updates["note"])
            else:
                from netwatcher.services.sensor_control import SensorControlRequest
                command = SensorControlRequest.from_bytes(candidate["command"].encode())
                engine_before, engine_previous, merged = self.control._candidate(command)
                self.control._apply_engine(command, engine_before, engine_previous, merged)
                await conn.execute("""UPDATE config_proposals SET status='approved',applied=true,apply_error=NULL,
                    decided_by=$2,decision_note=$3,decided_at=clock_timestamp() WHERE id=$1""", pid, request.actor_id, updates["note"])
        result = await self.entry(conn, request, pid)
        result["status"] = "applied"
        validate_result(request, result)
        if len(_json(result)) > 60000:
            raise SensorControlError("proposal_result_too_large", 503)
        await self.control._audit(conn, request, "sensor_change_applied",
            {"proposal_id": pid, "operation": request.operation, "after_version": result["base_version"]})
        await conn.execute("""UPDATE sensor_control_claims SET status='completed',result=$2,
            completed_at=clock_timestamp() WHERE request_id=$1""", UUID(request.request_id), result)
        return result
