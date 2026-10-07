"""최초 경보를 즉시 저장하고 반복 횟수를 유한한 창으로 집계한다."""

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import re
import time

from netwatcher.detection.models import Alert, Severity


@dataclass
class Window:
    event_id: int
    expires_at: float
    count: int
    first_seen: str
    last_seen: str
    severity: Severity

    def summary(self):
        return {"count": self.count, "first_seen": self.first_seen,
                "last_seen": self.last_seen, "max_severity": self.severity.value}


class AlertAggregator:
    def __init__(self, window_seconds=60, max_keys=10000, clock=time.monotonic):
        self.window_seconds = max(1, window_seconds)
        self.max_keys = max(1, max_keys)
        self.clock = clock
        self.active: dict[str, Window] = {}
        self.pending: deque[Window] = deque()
        self.overflow = 0

    @staticmethod
    def key(alert: Alert) -> str:
        # 소유자를 모르는 경보는 제목을 정규화해 다른 자산과 합치지 않는다.
        asset = alert.source_mac or alert.source_ip
        kind = alert.metadata.get("detection_type") or alert.title_key
        if not kind:
            kind = re.sub(r"\b\d+(?:\.\d+)?\b", "#", alert.title) if asset else alert.title
        identity = (alert.engine, asset, alert.dest_mac or alert.dest_ip, kind,
                    alert.metadata.get("policy_version", "unknown"),
                    alert.metadata.get("attack_stage"), alert.mitre_attack_id,
                    alert.packet_info.get("dst_port", alert.packet_info.get("dport")))
        return hashlib.sha256(json.dumps(identity, default=str).encode()).hexdigest()

    def _retire(self, key):
        window = self.active.pop(key)
        if window.count <= 1:
            return
        if len(self.pending) >= self.max_keys:
            self.overflow += window.count - 1
        else:
            self.pending.append(window)

    def repeat(self, alert: Alert) -> bool:
        key = self.key(alert)
        window = self.active.get(key)
        if window is None:
            return False
        if self.clock() >= window.expires_at or alert.severity > window.severity:
            self._retire(key)
            return False  # 창 만료 또는 심각도 상승은 새로운 대표 경보다.
        window.count += 1
        window.first_seen = min(window.first_seen, alert.timestamp)
        window.last_seen = max(window.last_seen, alert.timestamp)
        return True

    def register(self, alert: Alert, event_id: int) -> bool:
        if len(self.active) >= self.max_keys:
            self.overflow += 1
            return False
        self.active[self.key(alert)] = Window(event_id, self.clock() + self.window_seconds,
                                              1, alert.timestamp, alert.timestamp, alert.severity)
        return True

    def initial_summary(self, alert):
        return {"count": 1, "first_seen": alert.timestamp, "last_seen": alert.timestamp,
                "max_severity": alert.severity.value, "window_seconds": self.window_seconds}

    def expire(self, force=False):
        now = self.clock()
        for key, window in list(self.active.items()):
            if force or now >= window.expires_at:
                self._retire(key)

    async def flush(self, repository, force=False):
        self.expire(force)
        batch = list(self.pending)[:100]
        if not batch:
            return 0
        # 절대값을 저장하므로 commit 후 응답 유실에도 count가 이중 가산되지 않는다.
        await repository.update_aggregates([(w.event_id, w.summary()) for w in batch])
        for _ in batch:
            self.pending.popleft()
        return len(batch)
