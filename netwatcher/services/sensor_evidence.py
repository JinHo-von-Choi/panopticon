"""센서가 보관한 사건 PCAP을 경로 노출 없이 제한된 조각으로 제공한다."""

import base64
from collections import OrderedDict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

MAX_FILE_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 16 * 1024
PIN_BUDGET = {"files": 64, "bytes": MAX_FILE_BYTES, "max_hours": 24}


def version(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_nlink)


def validate_updates(operation, updates):
    fields = {"event_id"}
    if operation == "evidence.chunk": fields |= {"file_version", "offset"}
    if operation == "evidence.pin": fields |= {"enabled", "hours", "reason"}
    if set(updates) != fields or type(updates.get("event_id")) is not int or not 1 <= updates["event_id"] <= 2147483647:
        raise ValueError("Invalid evidence event")
    if operation == "evidence.chunk" and (not version(updates["file_version"])
            or type(updates["offset"]) is not int or not 0 <= updates["offset"] <= MAX_FILE_BYTES):
        raise ValueError("Invalid evidence chunk")
    if operation == "evidence.pin" and (type(updates["enabled"]) is not bool
            or type(updates["hours"]) is not int or not 1 <= updates["hours"] <= 24
            or not isinstance(updates["reason"], str) or not 3 <= len(updates["reason"].strip()) <= 500
            or "\x00" in updates["reason"]):
        raise ValueError("Invalid evidence review")


class SensorEvidence:
    def __init__(self, writer):
        self.writer = writer
        self._digests = OrderedDict()

    def _open(self, event_id):
        if self.writer is None:
            raise ValueError("Evidence storage is unavailable")
        path = self.writer.get_pcap_path(event_id)
        if not path:
            raise FileNotFoundError("Evidence file is unavailable")
        directory = os.open(self.writer._output_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        return descriptor

    def _file(self, descriptor, event_id, owner):
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 24 <= before.st_size <= MAX_FILE_BYTES:
            raise ValueError("Evidence file exceeds transfer policy")
        key = stamp(before)
        digest = self._digests.get(key)
        if digest is None:
            hasher = hashlib.sha256()
            position = 0
            while position < before.st_size:
                block = os.pread(descriptor, min(65536, before.st_size - position), position)
                if not block:
                    raise ValueError("Evidence file changed while hashing")
                hasher.update(block); position += len(block)
            digest = hasher.hexdigest()
            if stamp(os.fstat(descriptor)) != key:
                raise ValueError("Evidence file changed while hashing")
            self._digests[key] = digest
            while len(self._digests) > 64: self._digests.popitem(last=False)
        self._digests.move_to_end(key)
        opaque = hashlib.sha256(json.dumps([str(owner), event_id, key, digest]).encode()).hexdigest()
        return {"size": before.st_size, "sha256": digest, "file_version": opaque}, before

    def state(self, event_id, owner, generation, recorded_sha=None):
        if self.writer is None:
            state = {"event_id": event_id, "state": "unavailable", "pin_state": "unknown", "pin": None,
                "pin_budget": PIN_BUDGET, "size": None, "sha256": None, "file_version": None, "integrity": "unrecorded"}
            base = hashlib.sha256(json.dumps([str(owner), generation, state], sort_keys=True).encode()).hexdigest()
            return {**state, "base_version": base}
        with self.writer._file_lock:
            availability = self.writer.evidence_availability(event_id)
            file = {"size": None, "sha256": None, "file_version": None}
            if availability["state"] == "available":
                descriptor = self._open(event_id)
                try:
                    file, _ = self._file(descriptor, event_id, owner)
                finally:
                    os.close(descriptor)
                if recorded_sha is not None and recorded_sha != file["sha256"]:
                    raise ValueError("Evidence checksum differs from the stored record")
            state = {"event_id": event_id, **availability, **file,
                     "integrity": "matched_record" if recorded_sha and file["sha256"] else "unrecorded"}
            base = hashlib.sha256(json.dumps([str(owner), generation, state], sort_keys=True, allow_nan=False).encode()).hexdigest()
            return {**state, "base_version": base}

    def chunk(self, updates, owner, recorded_sha=None):
        if self.writer is None:
            raise ValueError("Evidence storage is unavailable")
        with self.writer._file_lock:
            descriptor = self._open(updates["event_id"])
            try:
                file, before = self._file(descriptor, updates["event_id"], owner)
                if file["file_version"] != updates["file_version"] or updates["offset"] > file["size"]:
                    raise ValueError("Evidence file version changed")
                if recorded_sha is not None and recorded_sha != file["sha256"]:
                    raise ValueError("Evidence checksum differs from the stored record")
                raw = os.pread(descriptor, min(CHUNK_BYTES, file["size"] - updates["offset"]), updates["offset"])
                if stamp(os.fstat(descriptor)) != stamp(before) or len(raw) != min(CHUNK_BYTES, file["size"] - updates["offset"]):
                    raise ValueError("Evidence file changed while reading")
                return {"event_id": updates["event_id"], "file_version": file["file_version"],
                    "offset": updates["offset"], "next_offset": updates["offset"] + len(raw),
                    "size": file["size"], "sha256": file["sha256"],
                    "data": base64.b64encode(raw).decode(), "chunk_sha256": hashlib.sha256(raw).hexdigest()}
            finally:
                os.close(descriptor)

    def pin(self, updates, actor, owner, file_version):
        with self.writer._file_lock:
            descriptor = self._open(updates["event_id"])
            try:
                file, _ = self._file(descriptor, updates["event_id"], owner)
                if file["file_version"] != file_version:
                    raise ValueError("Evidence file changed before pin")
                return self.writer.review_pin(updates["event_id"], actor=actor,
                    reason=updates["reason"].strip(), hours=updates["hours"], enabled=updates["enabled"])
            finally:
                os.close(descriptor)

    def check_pin(self, updates):
        if not updates["enabled"]:
            return
        with self.writer._file_lock:
            import time
            path = self.writer.get_pcap_path(updates["event_id"])
            if not path:
                raise FileNotFoundError("Evidence file is unavailable")
            names = {name for name, pin in self.writer._pins.items() if pin["expires_at"] > time.time()}
            names.add(Path(path).name)
            total = sum(size for _, file, size in self.writer._inventory if file.name in names)
            if len(names) > PIN_BUDGET["files"] or total > PIN_BUDGET["bytes"]:
                raise ValueError("Evidence pin budget exceeded")


def validate_state(state, event_id):
    fields = {"event_id", "state", "pin_state", "pin", "pin_budget", "size", "sha256", "file_version", "integrity", "base_version"}
    if (not isinstance(state, dict) or set(state) != fields or type(state["event_id"]) is not int or state["event_id"] != event_id
            or state["state"] not in {"available", "unavailable"} or state["pin_state"] not in {"pinned", "unpinned", "unknown"}
            or state["pin_budget"] != PIN_BUDGET or not version(state["base_version"])
            or state["integrity"] not in {"matched_record", "unrecorded"}):
        raise ValueError("Invalid evidence state")
    if state["state"] == "available":
        if type(state["size"]) is not int or not 24 <= state["size"] <= MAX_FILE_BYTES or not version(state["sha256"]) or not version(state["file_version"]):
            raise ValueError("Invalid evidence file metadata")
    elif any(state[key] is not None for key in ("size", "sha256", "file_version")):
        raise ValueError("Unavailable file has metadata")
    pin = state["pin"]
    if state["pin_state"] == "pinned":
        if (not isinstance(pin, dict) or set(pin) != {"expires_at", "confirmed_by", "reason"}
                or type(pin["expires_at"]) not in (int, float) or not math.isfinite(pin["expires_at"])
                or not isinstance(pin["confirmed_by"], str) or len(pin["confirmed_by"]) > 255
                or not isinstance(pin["reason"], str) or len(pin["reason"]) > 500):
            raise ValueError("Invalid evidence pin")
    elif pin is not None:
        raise ValueError("Inactive pin has metadata")


def validate_result(request, result):
    updates = json.loads(request.updates_json)
    fields = {"status", "request_id"}
    if request.operation == "evidence.chunk":
        fields |= {"event_id", "file_version", "offset", "next_offset", "size", "sha256", "data", "chunk_sha256"}
        if (type(result.get("event_id")) is not int or result.get("event_id") != updates["event_id"]
                or type(result.get("offset")) is not int or result.get("offset") != updates["offset"]
                or type(result.get("next_offset")) is not int
                or result.get("file_version") != updates["file_version"] or type(result.get("size")) is not int
                or not 24 <= result["size"] <= MAX_FILE_BYTES or not isinstance(result.get("data"), str)
                or len(result["data"]) > 4 * ((CHUNK_BYTES + 2) // 3) or not version(result.get("sha256"))):
            raise ValueError("Invalid evidence chunk")
        raw = base64.b64decode(result["data"], validate=True)
        if (len(raw) != min(CHUNK_BYTES, result["size"] - updates["offset"])
                or result.get("next_offset") != updates["offset"] + len(raw)
                or result.get("chunk_sha256") != hashlib.sha256(raw).hexdigest()):
            raise ValueError("Invalid evidence chunk bytes")
    else:
        fields.add("evidence")
        validate_state(result.get("evidence"), updates["event_id"])
        if request.operation == "evidence.pin" and result["evidence"]["pin_state"] != ("pinned" if updates["enabled"] else "unpinned"):
            raise ValueError("Unconfirmed evidence pin")
    if (set(result) != fields or result["request_id"] != request.request_id
            or result["status"] != ("applied" if request.operation == "evidence.pin" else "read")):
        raise ValueError("Invalid evidence result")
