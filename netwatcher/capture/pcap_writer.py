"""알림 발생 시 포렌식 패킷 캡처를 위한 PCAP 파일 기록기."""

from __future__ import annotations

import logging
import json
import math
import os
import time
import threading
from collections import deque
from pathlib import Path

from scapy.all import IP, IPv6, ARP, Ether, Packet
from scapy.utils import RawPcapWriter
from netwatcher.web import metrics

logger = logging.getLogger("netwatcher.capture.pcap_writer")


class PCAPWriter:
    """최근 패킷의 ring buffer를 유지하고 요청 시 PCAP 파일을 기록한다.

    알림 발생 시, 시간 윈도우 내에서 src/dst가 일치하는 관련 패킷을
    포렌식 분석용 PCAP 파일로 저장한다.
    """

    def __init__(
        self,
        output_dir: str = "data/pcaps",
        buffer_size: int = 1000,
        context_seconds: float = 5.0,
        max_storage_mb: int = 500,
        max_buffer_bytes: int = 8 * 1024 * 1024,
        max_deletes_per_second: int = 4,
        max_files: int = 10000,
    ) -> None:
        """PCAP 기록기를 초기화한다. 출력 디렉토리, 버퍼 크기, 저장 제한을 설정한다."""
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._file_lock = threading.RLock()
        self._pins_path = self._output_dir / "review-pins.json"
        self._pins = {}
        self._pins_valid = True
        try:
            if self._pins_path.is_symlink():
                raise ValueError("Invalid pin manifest")
            if self._pins_path.exists():
                if self._pins_path.stat().st_size > 65536:
                    raise ValueError("Pin manifest exceeds budget")
                pins = json.loads(self._pins_path.read_text())
                if not isinstance(pins, dict) or len(pins) > 64:
                    raise ValueError("Invalid pin manifest")
                for name, pin in pins.items():
                    if (Path(name).name != name or not name.startswith("event_") or not name.endswith(".pcap")
                            or not isinstance(pin, dict) or not math.isfinite(float(pin["expires_at"]))):
                        raise ValueError("Invalid pin manifest")
                self._pins = pins
        except Exception:
            self._pins_valid = False
            logger.warning("Evidence pin manifest invalid; retention and new writes disabled")
        self._buffer_size = buffer_size
        self._context_seconds = context_seconds
        self._max_storage_bytes = max_storage_mb * 1024 * 1024
        self._max_buffer_bytes = max(1, max_buffer_bytes)
        self._buffer_bytes = 0
        self._lock = threading.Lock()
        self._max_deletes = max(1, max_deletes_per_second)
        self._delete_epoch = 0.0
        self._deleted_this_second = 0
        self._last_retention = 0.0
        self._max_files = max(1, max_files)
        self._inventory_complete = True
        # 파일 재고는 시작 시 한 번 구축하고 이후 쓰기/삭제로 갱신한다.
        inventory = []
        for path in self._output_dir.glob("*.pcap"):
            stat = path.stat()
            if len(inventory) < self._max_files:
                inventory.append((stat.st_mtime, path, stat.st_size))
            else:
                self._inventory_complete = False
        self._inventory = deque(sorted(inventory, key=lambda item: item[0]))
        self._storage_bytes = sum(item[2] for item in inventory)
        metrics.pcap_operations.labels(operation="scan", result="ok").inc()
        if not self._inventory_complete:
            logger.warning("PCAP inventory exceeds file budget; new evidence writes are disabled")

        # Ring buffer: (타임스탬프, 패킷) 쌍의 deque
        self._buffer = deque()
        self._asset_usage = {}

    def add_packet(self, packet: Packet) -> None:
        """패킷을 ring buffer에 추가한다."""
        raw = bytes(packet)
        if len(raw) > self._max_buffer_bytes:
            return
        layer = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        source = layer.src if layer is not None else packet[ARP].psrc if ARP in packet else None
        dest = layer.dst if layer is not None else packet[ARP].pdst if ARP in packet else None
        with self._lock:
            self._buffer.append((time.time(), raw, source, dest, 1 if Ether in packet else 101))
            self._buffer_bytes += len(raw)
            count, size = self._asset_usage.get(source, (0, 0))
            self._asset_usage[source] = (count + 1, size + len(raw))
            while (self._asset_usage.get(source, (0, 0))[0] > max(1, self._buffer_size // 4)
                   or self._asset_usage.get(source, (0, 0))[1] > max(len(raw), self._max_buffer_bytes // 4)):
                index = next(i for i, record in enumerate(self._buffer) if record[2] == source)
                self._buffer.rotate(-index)
                self._remove_oldest()
                self._buffer.rotate(index)
            while self._buffer and (len(self._buffer) > self._buffer_size or self._buffer_bytes > self._max_buffer_bytes):
                self._remove_oldest()

    def _remove_oldest(self):
        _, raw, source, _, _ = self._buffer.popleft()
        self._buffer_bytes -= len(raw)
        count, size = self._asset_usage[source]
        if count == 1:
            del self._asset_usage[source]
        else:
            self._asset_usage[source] = (count - 1, size - len(raw))

    def snapshot(self, source_ip, dest_ip, alert_timestamp=None):
        """패킷 변경과 파일 I/O에서 분리된 불변 raw 바이트 스냅샷."""
        if not source_ip and not dest_ip:
            return ()
        now = alert_timestamp if alert_timestamp is not None else time.time()
        with self._lock:
            return tuple((ts, raw, linktype) for ts, raw, src, dst, linktype in self._buffer
                         if now - self._context_seconds <= ts <= now
                         and ((source_ip and source_ip in (src, dst)) or
                              (dest_ip and dest_ip in (src, dst))))

    def capture_for_alert(
        self,
        event_id: int,
        source_ip: str | None,
        dest_ip: str | None,
        alert_timestamp: float | None = None,
    ) -> str | None:
        """알림 관련 패킷이 포함된 PCAP 파일을 기록한다.

        패킷이 캡처되면 파일 경로를 반환하고, 없으면 None을 반환한다.
        """
        matching = self.snapshot(source_ip, dest_ip, alert_timestamp)
        return self.write_snapshot(event_id, matching)

    def write_snapshot(self, event_id, matching):
        with self._file_lock:
            return self._write_snapshot(event_id, matching)

    def _write_snapshot(self, event_id, matching):
        if not matching:
            return None
        if not self._inventory_complete or not self._pins_valid:
            return None
        now = time.time()
        projected = 24 + sum(16 + len(raw) for _, raw, _ in matching)
        if self._storage_bytes + projected > self._max_storage_bytes or len(self._inventory) >= self._max_files:
            self._enforce_storage_limit(required_bytes=projected, required_files=1)
        if self._storage_bytes + projected > self._max_storage_bytes or len(self._inventory) >= self._max_files:
            return None
        filename = f"event_{event_id}_{time.time_ns()}.pcap"
        filepath = self._output_dir / filename
        temporary = filepath.with_suffix(".pcap.part")

        try:
            started = time.monotonic()
            try:
                linktype = matching[0][2]
                with RawPcapWriter(str(temporary), linktype=linktype) as writer:
                    writer.write_header(None)
                    for ts, raw, packet_linktype in matching:
                        if packet_linktype != linktype:
                            raise ValueError("Mixed link types cannot share one PCAP")
                        writer.write_packet(raw, sec=int(ts), usec=int((ts % 1) * 1000000))
                os.replace(temporary, filepath)
                size = filepath.stat().st_size
                self._inventory.append((now, filepath, size))
                self._storage_bytes += size
            except Exception:
                metrics.pcap_operations.labels(operation="write", result="failed").inc()
                raise
            else:
                metrics.pcap_operations.labels(operation="write", result="ok").inc()
            finally:
                metrics.pcap_duration.labels(operation="write").observe(time.monotonic() - started)
            logger.info(
                "PCAP captured: %s (%d packets)", filename, len(matching)
            )

            # 저장 용량 제한 적용
            self._enforce_storage_limit()

            return str(filepath)
        except Exception:
            temporary.unlink(missing_ok=True)
            logger.exception("Failed to write PCAP: %s", filename)
            return None

    def _enforce_storage_limit(self, required_bytes=0, required_files=0) -> None:
        with self._file_lock:
            if self._pins_valid:
                self._retention(required_bytes, required_files)

    def _retention(self, required_bytes=0, required_files=0) -> None:
        """전체 저장 용량이 제한을 초과하면 가장 오래된 PCAP 파일을 삭제한다."""
        started = time.monotonic()
        try:
            now = time.monotonic()
            if now - self._delete_epoch >= 1:
                self._delete_epoch = now
                self._deleted_this_second = 0
            self._last_retention = now
            while ((self._storage_bytes + required_bytes > self._max_storage_bytes
                    or len(self._inventory) + required_files > self._max_files)
                   and self._inventory and self._deleted_this_second < self._max_deletes):
                victim = next((item for item in self._inventory
                               if self._pins.get(item[1].name, {}).get('expires_at', 0) <= time.time()), None)
                if victim is None:
                    break  # pinned evidence is preserved; new writes may be refused
                _, oldest, size = victim
                oldest.unlink(missing_ok=True)
                self._inventory.remove(victim)
                self._storage_bytes -= size
                self._deleted_this_second += 1
                metrics.pcap_operations.labels(operation="delete", result="ok").inc()
                logger.info("Deleted old PCAP: %s", oldest.name)
        except Exception:
            metrics.pcap_operations.labels(operation="retention", result="failed").inc()
            logger.exception("Error enforcing PCAP storage limit")
        finally:
            metrics.pcap_duration.labels(operation="retention").observe(time.monotonic() - started)

    def _save_pins(self, pins):
        temporary = self._pins_path.with_suffix('.json.part')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(pins, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._pins_path)
            self._pins = pins  # retain protection even if directory fsync is unconfirmed
            directory = os.open(self._output_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def review_pin(self, event_id, *, actor, reason, hours=24, enabled=True):
        with self._file_lock:
            if not self._pins_valid:
                raise ValueError('Evidence pin state unavailable')
            path = self.get_pcap_path(event_id)
            if not path:
                raise FileNotFoundError('Evidence file is unavailable')
            now = time.time()
            pins = {name: pin for name, pin in self._pins.items() if pin['expires_at'] > now}
            name = Path(path).name
            if enabled:
                if not 1 <= hours <= 24:
                    raise ValueError('Pin TTL must be 1..24 hours')
                expires = max(pins.get(name, {}).get('expires_at', 0), now + hours * 3600)
                pins[name] = {'expires_at': expires, 'confirmed_by': actor[:255], 'reason': reason[:500]}
                total = sum(size for _, file, size in self._inventory if file.name in pins)
                if len(pins) > 64 or total > 32 * 1024 * 1024:
                    raise ValueError('Evidence pin budget exceeded (64 files / 32 MiB)')
            else:
                pins.pop(name, None)
            self._save_pins(pins)
            self._pins = pins
            return self.evidence_availability(event_id)

    def evidence_availability(self, event_id):
        with self._file_lock:
            path = self.get_pcap_path(event_id)
            pin = self._pins.get(Path(path).name, {}) if path else {}
            return {'state': 'available' if path else 'unavailable',
                    'pin_state': 'unknown' if not self._pins_valid else
                        'pinned' if pin.get('expires_at', 0) > time.time() else 'unpinned',
                    'pin': pin if pin.get('expires_at', 0) > time.time() else None,
                    'pin_budget': {'files': 64, 'bytes': 32 * 1024 * 1024, 'max_hours': 24}}

    def get_pcap_path(self, event_id: int) -> str | None:
        """이벤트 ID에 해당하는 PCAP 파일을 찾는다."""
        with self._file_lock:
            for _, path, _ in reversed(self._inventory):
                if path.name.startswith(f"event_{int(event_id)}_") and path.is_file() and not path.is_symlink():
                    return str(path)
        return None
