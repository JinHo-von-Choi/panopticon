"""Optional, bounded JSON recovery journal for DB failures (never pickle).

Only failed, UUID-addressed batches enter the spool. fsync precedes reporting
persistence. Limits refuse new records instead of evicting pending evidence.
"""
from __future__ import annotations
import json
import math
import os
import threading
import time
import uuid
from pathlib import Path


class RecoverySpool:
    def __init__(self, directory, *, max_bytes=16*1024*1024, max_files=64, ttl=300):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_bytes = max(1024, min(64*1024*1024, int(max_bytes)))
        self.max_files = max(1, min(256, int(max_files)))
        self.ttl = max(1, min(86400, int(ttl)))
        self._lock = threading.RLock()
        self._inventory = {}
        self._invalid = any(self.directory.glob("*.json.part"))
        self.expired_records = 0
        self.recovered_records = 0
        self.refused_records = 0
        for path in self.directory.glob('*.json'):
            if len(self._inventory) >= self.max_files or path.is_symlink():
                self._invalid = True
                break
            try:
                uuid.UUID(path.stem)
                self._inventory[path.name] = path.stat().st_size
            except (ValueError, OSError):
                self._invalid = True
        if sum(self._inventory.values()) > self.max_bytes:
            self._invalid = True

    def status(self):
        return {'state': 'invalid' if self._invalid else 'pending' if self._inventory else 'empty',
                'files': len(self._inventory), 'bytes': sum(self._inventory.values()),
                'max_files': self.max_files, 'max_bytes': self.max_bytes, 'ttl_seconds': self.ttl,
                'expired_records': self.expired_records, 'recovered_records': self.recovered_records,
                'refused_records': self.refused_records}

    def _fsync_directory(self):
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def put(self, key, payload, *, count=1):
        with self._lock:
            name = uuid.UUID(str(key)).hex + '.json'
            if name in self._inventory:
                return True  # same immutable receipt; no repeated HDD write
            frame = {'version': 1, 'created_at': time.time(), 'count': int(count), 'payload': payload}
            def encode(value):
                if isinstance(value, set):
                    return sorted(value)
                raise TypeError('Unsupported recovery payload')
            data = json.dumps(frame, ensure_ascii=False, allow_nan=False, default=encode).encode()
            if (self._invalid or len(data) > 1024*1024 or len(self._inventory) >= self.max_files
                    or sum(self._inventory.values()) + len(data) > self.max_bytes):
                self.refused_records += count
                return False
            path = self.directory / name
            temporary = path.with_suffix('.json.part')
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
                self._inventory[name] = len(data)
                self._fsync_directory()
            finally:
                temporary.unlink(missing_ok=True)
            return True

    def next(self):
        with self._lock:
            if self._invalid:
                return None
            for name in tuple(self._inventory):
                path = self.directory / name
                try:
                    if path.is_symlink() or path.stat().st_size > 1024*1024:
                        raise ValueError('Invalid spool frame')
                    frame = json.loads(path.read_bytes())
                    created = frame['created_at']
                    if (frame['version'] != 1 or not isinstance(frame['count'], int) or frame['count'] < 1
                            or not math.isfinite(created) or created > time.time() + 60):
                        raise ValueError('Invalid spool frame')
                    if time.time() - created >= self.ttl:
                        self.expired_records += frame['count']
                        self.ack(name, recovered=0)
                        continue
                    return name, frame
                except (KeyError, TypeError, ValueError, OSError):
                    self._invalid = True
                    return None  # preserve uncertain records; no silent overwrite
            return None

    def ack(self, name, *, recovered=0):
        with self._lock:
            if name not in self._inventory:
                raise ValueError('Unknown spool receipt')
            (self.directory / name).unlink(missing_ok=True)
            self._fsync_directory()
            self._inventory.pop(name)
            self.recovered_records += recovered
