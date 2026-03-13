"""알림 집약 파이프라인: 중복 제거 -> 유사 집약 -> 메타 알림 생성.

작성자: 최진호
작성일: 2026-03-13
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from netwatcher.detection.models import Alert, Severity


@dataclass
class MetaAlert:
    """집약된 알림 그룹."""
    engine: str
    severity: Severity
    title: str
    source_ip: str
    count: int
    unique_targets: int
    first_seen: float
    last_seen: float
    sample_alerts: list[Alert] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "severity": self.severity.value,
            "title": self.title,
            "source_ip": self.source_ip,
            "count": self.count,
            "unique_targets": self.unique_targets,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sample_alerts": [a.to_dict() for a in self.sample_alerts[:3]],
        }


class AlertAggregator:
    """3단계 알림 집약 파이프라인.

    1단계 Deduplication: (engine, source_ip, dest_ip, title) 기준 윈도우 내 중복 제거
    2단계 Aggregation: 동일 (engine, source_ip) 그룹의 다른 대상 알림 묶음
    3단계 Meta-Alert: 집약된 그룹에서 요약 알림 생성
    """

    def __init__(self, window_seconds: int = 60, max_samples: int = 3):
        self._window = window_seconds
        self._max_samples = max_samples

        # 1단계: dedup 키 -> (첫 알림 시각, 카운트)
        self._dedup: dict[str, tuple[float, int]] = {}

        # 2단계: (engine, source_ip) -> {dest_ips: set, alerts: list, first_seen, last_seen}
        self._groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"dest_ips": set(), "alerts": [], "first_seen": 0.0, "last_seen": 0.0, "severity": Severity.INFO}
        )

    def submit(self, alert: Alert) -> Alert | MetaAlert | None:
        """알림을 제출한다. 전달해야 할 알림/메타알림을 반환하고, 억제하면 None."""
        now = time.time()
        self._cleanup(now)

        # 1단계: Deduplication
        dedup_key = f"{alert.engine}:{alert.source_ip}:{alert.dest_ip}:{alert.title}"
        if dedup_key in self._dedup:
            first_time, count = self._dedup[dedup_key]
            self._dedup[dedup_key] = (first_time, count + 1)
            return None  # 중복 억제

        self._dedup[dedup_key] = (now, 1)

        # 2단계: Aggregation
        group_key = (alert.engine, alert.source_ip or "")
        group = self._groups[group_key]

        if group["first_seen"] == 0.0:
            group["first_seen"] = now
        group["last_seen"] = now
        group["dest_ips"].add(alert.dest_ip or "")
        if len(group["alerts"]) < self._max_samples:
            group["alerts"].append(alert)
        if alert.severity > group["severity"]:
            group["severity"] = alert.severity

        # 3단계: 첫 알림이면 그대로 전달, 이미 그룹이 있으면 메타알림 반환
        if len(group["dest_ips"]) <= 1:
            return alert

        return MetaAlert(
            engine=alert.engine,
            severity=group["severity"],
            title=self._make_title(alert, len(group["dest_ips"])),
            source_ip=alert.source_ip or "",
            count=len(group["dest_ips"]),
            unique_targets=len(group["dest_ips"]),
            first_seen=group["first_seen"],
            last_seen=group["last_seen"],
            sample_alerts=group["alerts"][:self._max_samples],
        )

    def flush(self) -> list[MetaAlert]:
        """모든 활성 그룹을 메타알림으로 변환하여 반환하고 상태를 초기화한다."""
        results = []
        for (engine, source_ip), group in self._groups.items():
            if len(group["dest_ips"]) > 0:
                title = f"{engine}: {source_ip} -> {len(group['dest_ips'])} targets"
                results.append(MetaAlert(
                    engine=engine,
                    severity=group["severity"],
                    title=title,
                    source_ip=source_ip,
                    count=len(group["dest_ips"]),
                    unique_targets=len(group["dest_ips"]),
                    first_seen=group["first_seen"],
                    last_seen=group["last_seen"],
                    sample_alerts=group["alerts"][:self._max_samples],
                ))
        self._groups.clear()
        self._dedup.clear()
        return results

    def _cleanup(self, now: float) -> None:
        """윈도우 밖의 오래된 항목을 정리한다."""
        cutoff = now - self._window

        expired_dedup = [k for k, (ts, _) in self._dedup.items() if ts < cutoff]
        for k in expired_dedup:
            del self._dedup[k]

        expired_groups = [
            k for k, g in self._groups.items() if g["last_seen"] < cutoff
        ]
        for k in expired_groups:
            del self._groups[k]

    def _make_title(self, alert: Alert, target_count: int) -> str:
        """집약된 알림의 제목을 생성한다."""
        return f"{alert.title}: {alert.source_ip} -> {target_count} targets"
