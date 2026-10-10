"""지정 디렉터리의 EVE 파일을 제한된 배치로 읽는다."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path

from netwatcher.ingest.eve import MAX_LINE_BYTES, decode_eve_line


class EveTailer:
    def __init__(self, repository, *, directory, filename="eve.json", sensor_id, source_id,
                 batch_records=128, batch_bytes=1024 * 1024, rotation_grace=2.0):
        if filename in {".", ".."} or Path(filename).name != filename or not filename:
            raise ValueError("EVE filename must be a single filename")
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value) for value in (sensor_id, source_id)):
            raise ValueError("Invalid EVE source identifier")
        if not 1 <= batch_records <= 1024 or not MAX_LINE_BYTES + 1 <= batch_bytes <= 4 * 1024 * 1024:
            raise ValueError("Invalid EVE batch budget")
        if not 0 <= rotation_grace <= 60:
            raise ValueError("Invalid EVE rotation grace")
        self.repository = repository
        self.directory = Path(directory).absolute()
        self.filename = filename
        self.sensor_id, self.source_id = sensor_id, source_id
        self.batch_records, self.batch_bytes = batch_records, batch_bytes
        self.rotation_grace = rotation_grace
        self._revision, self._state = None, None
        self._loaded = False
        self._directory_fd = self._file_fd = None
        self._io_lock = threading.RLock()
        self._poll_lock = asyncio.Lock()
        self._rotation_since = None
        self.last_error = None
        self.last_poll = None
        self._batch_bytes_limited = False

    def _open(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._directory_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError("EVE input must be a regular file")
        return fd

    @staticmethod
    def _identity(fd):
        info = os.fstat(fd)
        return [info.st_dev, info.st_ino]

    @staticmethod
    def _anchor(fd, offset):
        return hashlib.sha256(os.pread(fd, min(offset, 64), max(0, offset - 64))).hexdigest()

    def _close_file(self):
        if self._file_fd is not None:
            os.close(self._file_fd)
            self._file_fd = None
        self._rotation_since = None

    def close(self):
        with self._io_lock:
            self._close_file()
            if self._directory_fd is not None:
                os.close(self._directory_fd)
                self._directory_fd = None

    def _find_old(self, identity):
        with os.scandir(self._directory_fd) as files:
            for count, entry in enumerate(files):
                if count >= 128:
                    raise ValueError("EVE rotation directory exceeds scan budget")
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode) and [info.st_dev, info.st_ino] == identity:
                        fd = self._open(entry.name)
                        if self._identity(fd) == identity:
                            return fd
                        os.close(fd)
                except FileNotFoundError:
                    continue
        return None

    def _notice(self, state, reason, raw=b"", *, offset=None):
        start = state["offset"] if offset is None else offset
        return {"ingest_id": str(uuid.uuid5(uuid.NAMESPACE_URL,
                    f"panopticon:eve:{self.sensor_id}:{self.source_id}:{state['generation']}:{start}:{reason}")),
                "sensor_id": self.sensor_id, "source_id": self.source_id,
                "event_type": "_gap" if reason in {"rotated_source_missing", "copy_truncate", "rotated_partial_line"} else "_rejected",
                "supported": False, "reason": reason,
                "original_ref": {"generation": state["generation"], "offset": start,
                                 "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                 "partial": reason == "line_too_large"}}

    def _new_state(self):
        return {"generation": str(uuid.uuid4()), "file_identity": self._identity(self._file_fd),
                "offset": 0, "anchor": self._anchor(self._file_fd, 0), "skipping": False}

    def _read_batch(self):
        with self._io_lock:
            if self._directory_fd is None:
                self._directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            state = dict(self._state) if self._state else None
            records = []
            if self._file_fd is not None and state and self._identity(self._file_fd) != state["file_identity"]:
                self._close_file()
            if self._file_fd is None:
                self._file_fd = self._find_old(state["file_identity"]) if state else None
                if self._file_fd is None:
                    if state:
                        records.append(self._notice(state, "rotated_source_missing"))
                    self._file_fd = self._open(self.filename)
                    state = self._new_state()
            state = state or self._new_state()
            if (os.fstat(self._file_fd).st_size < state["offset"] or
                    self._anchor(self._file_fd, state["offset"]) != state["anchor"]):
                records.append(self._notice(state, "copy_truncate"))
                state = self._new_state()
            consumed = 0
            buffer = os.pread(self._file_fd, self.batch_bytes, state["offset"])
            self._batch_bytes_limited = len(buffer) == self.batch_bytes
            while len(records) < self.batch_records and consumed < self.batch_bytes:
                remaining = self.batch_bytes - consumed
                end = consumed + min(MAX_LINE_BYTES + 1, remaining)
                newline = buffer.find(b"\n", consumed, end)
                raw = buffer[consumed:newline + 1 if newline >= 0 else end]
                if newline < 0 and len(raw) <= MAX_LINE_BYTES and not state["skipping"]:
                    break  # 아직 쓰는 중인 JSON 행은 다음 배치에서 다시 읽는다.
                if not raw:
                    break
                start = state["offset"]
                if state["skipping"]:
                    state["skipping"] = newline < 0
                elif len(raw) > MAX_LINE_BYTES:
                    records.append(self._notice(state, "line_too_large", raw))
                    state["skipping"] = newline < 0
                else:
                    try:
                        records.append(decode_eve_line(raw, sensor_id=self.sensor_id, source_id=self.source_id,
                                                       generation=state["generation"], offset=start,
                                                       feeds=getattr(self.repository, "feeds", None)))
                    except (ValueError, UnicodeDecodeError, RecursionError):
                        records.append(self._notice(state, "invalid_record", raw))
                state["offset"] += len(raw)
                consumed += len(raw)
            # 교체된 파일의 마지막 행까지 먼저 읽는다. 지연 쓰기는 유예 시간 동안 기다린다.
            try:
                current = os.stat(self.filename, dir_fd=self._directory_fd, follow_symlinks=False)
                replaced = [current.st_dev, current.st_ino] != state["file_identity"]
            except FileNotFoundError:
                replaced = False
            if replaced and not consumed:
                now = time.monotonic()
                self._rotation_since = self._rotation_since or now
                if now - self._rotation_since >= self.rotation_grace:
                    partial = os.pread(self._file_fd, MAX_LINE_BYTES, state["offset"])
                    if partial:
                        records.append(self._notice(state, "rotated_partial_line", partial))
                    candidate = self._open(self.filename)
                    self._close_file()
                    self._file_fd = candidate
                    state = self._new_state()
            elif consumed:
                self._rotation_since = None
            state["anchor"] = self._anchor(self._file_fd, state["offset"])
            for name, kind in (("gaps", "_gap"), ("rejected", "_rejected")):
                state[name] = (self._state or {}).get(name, 0) + sum(record["event_type"] == kind for record in records)
            return state, records

    async def poll_once(self):
        async with self._poll_lock:
            if not self._loaded:
                async with asyncio.timeout(5):
                    self._revision, self._state = await self.repository.load(self.sensor_id, self.source_id)
                self._loaded = True
            state, records = await asyncio.to_thread(self._read_batch)
            if state == self._state and not records:
                self.last_poll = time.monotonic()
                self.last_error = None
                return 0
            try:
                async with asyncio.timeout(5):
                    revision = await self.repository.commit(self.sensor_id, self.source_id, self._revision, state, records)
            except BaseException:
                # COMMIT 응답만 유실됐을 수도 있으므로 다음 시도는 DB 위치부터 다시 읽는다.
                self._loaded = False
                raise
            self._revision, self._state = revision, state
            self.last_error = None
            self.last_poll = time.monotonic()
            return len(records)

    def _pending_bytes(self, state):
        with self._io_lock:
            if self._file_fd is None:
                return None
            try:
                info = os.fstat(self._file_fd)
            except OSError:
                return None
            offset = state.get("offset")
            if ([info.st_dev, info.st_ino] != state.get("file_identity")
                    or type(offset) is not int or not 0 <= offset <= info.st_size):
                return None
            return info.st_size - offset

    def status(self):
        stale = self.last_poll is None or time.monotonic() - self.last_poll > 30
        state = self._state or {}
        pending = self._pending_bytes(state)
        backlog = pending is not None and pending > 2 * self.batch_bytes
        degraded = state.get("gaps") or state.get("rejected") or backlog or pending is None
        return {"status": "unhealthy" if self.last_error or stale else
                "degraded" if degraded else "healthy",
                "sensor_id": self.sensor_id, "source_id": self.source_id,
                "error": self.last_error, "gaps": state.get("gaps", 0),
                "rejected": state.get("rejected", 0), "committed_offset": state.get("offset"),
                "pending_bytes": pending, "pending_scope": "active_file", "backlog": backlog,
                "capture_loss": "unknown", "scope": "configured_eve_file"}

    async def run(self, stop, interval=0.1):
        try:
            while not stop.is_set():
                try:
                    processed = await self.poll_once()
                    if processed >= self.batch_records or self._batch_bytes_limited:
                        await asyncio.sleep(0)
                        continue
                except Exception as exc:
                    self.last_error = type(exc).__name__
                try:
                    await asyncio.wait_for(stop.wait(), timeout=interval if self.last_error is None else 1.0)
                except TimeoutError:
                    continue
        finally:
            await asyncio.to_thread(self.close)
