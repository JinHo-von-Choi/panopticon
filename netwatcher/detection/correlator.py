"""알림 상관분석 엔진: 관련 알림을 인시던트로 그룹화하고 DB에 영속화한다."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.detection.correlator")

# 킬체인 단계 매핑
_KILL_CHAIN_STAGES = {
    "port_scan": "reconnaissance",
    "icmp_anomaly": "reconnaissance",
    "arp_spoof": "initial_access",
    "dhcp_spoof": "initial_access",
    "dns_anomaly": "command_and_control",
    "threat_intel": "command_and_control",
    "http_suspicious": "command_and_control",
    "lateral_movement": "lateral_movement",
    "ransomware_lateral": "lateral_movement",
    "mac_spoof": "defense_evasion",
    "protocol_anomaly": "defense_evasion",
    "data_exfil": "exfiltration",
    "traffic_anomaly": "anomaly",
}

# 킬체인 진행 순서
_KILL_CHAIN_ORDER = [
    "reconnaissance",
    "initial_access",
    "command_and_control",
    "lateral_movement",
    "defense_evasion",
    "exfiltration",
]


@dataclass
class Incident:
    """상관분석된 알림 그룹."""
    id: int
    severity: Severity
    title: str
    description: str
    alert_ids: list[int] = field(default_factory=list)
    source_ips: set[str] = field(default_factory=set)
    engines: set[str] = field(default_factory=set)
    kill_chain_stages: list[str] = field(default_factory=list)
    rule: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    )
    updated_at: str = ""
    resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        """인시던트를 딕셔너리로 직렬화한다."""
        return {
            "id": self.id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "alert_ids": self.alert_ids,
            "source_ips": sorted(self.source_ips),
            "engines": sorted(self.engines),
            "kill_chain_stages": self.kill_chain_stages,
            "rule": self.rule,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "resolved": self.resolved,
        }


class AlertCorrelator:
    """시간적, 출발지 관계를 기반으로 알림을 인시던트로 상관분석한다."""

    def __init__(
        self,
        time_window: int = 300,
        burst_threshold: int = 5,
        burst_window: int = 60,
        incident_repo=None,
    ) -> None:
        """상관분석기를 초기화한다. 시간 윈도우, 버스트 임계값 등을 설정한다."""
        self._time_window     = time_window
        self._burst_threshold = burst_threshold
        self._burst_window    = burst_window
        self._incident_repo   = incident_repo

        # 인메모리 캐시 (빠른 조회를 위해 최근 100개 인시던트로 제한)
        self._incidents: list[Incident] = []
        self._next_id = 1

        # 상관분석용 최근 알림: source_ip -> deque of (timestamp, alert_info)
        self._recent_alerts: dict[str, deque[tuple[float, dict[str, Any]]]] = defaultdict(deque)
        # 버스트 탐지용 알림 횟수 추적
        self._alert_counts: dict[str, deque[float]] = defaultdict(deque)

    def set_incident_repo(self, repo) -> None:
        """생성 후 인시던트 저장소를 주입한다."""
        self._incident_repo = repo

    def process_alert(self, alert: Alert, event_id: int | None = None) -> Incident | None:
        """알림을 처리하고 상관분석이 트리거되면 인시던트를 반환한다."""
        now    = time.time()
        source = alert.source_ip or alert.source_mac or ""
        if not source:
            return None

        alert_info = {
            "event_id": event_id,
            "engine": alert.engine,
            "severity": alert.severity,
            "title": alert.title,
            "kill_chain_stage": _KILL_CHAIN_STAGES.get(alert.engine, "unknown"),
        }

        self._recent_alerts[source].append((now, alert_info))
        self._alert_counts[source].append(now)

        # 오래된 항목 제거
        cutoff = now - self._time_window
        while self._recent_alerts[source] and self._recent_alerts[source][0][0] < cutoff:
            self._recent_alerts[source].popleft()

        burst_cutoff = now - self._burst_window
        while self._alert_counts[source] and self._alert_counts[source][0] < burst_cutoff:
            self._alert_counts[source].popleft()

        # 상관분석 규칙 검사
        incident = None

        # 규칙 1: 다중 엔진 상관분석 (시간 윈도우 내 다른 엔진)
        recent = self._recent_alerts[source]
        engines = set(info["engine"] for _, info in recent)
        if len(engines) >= 2:
            incident = self._create_or_update_incident(
                source, recent, "multi_engine"
            )

        # 규칙 2: Kill chain 진행
        stages = [
            info["kill_chain_stage"] for _, info in recent
            if info["kill_chain_stage"] in _KILL_CHAIN_ORDER
        ]
        unique_stages = []
        for s in stages:
            if s not in unique_stages:
                unique_stages.append(s)

        if len(unique_stages) >= 2:
            # 단계가 kill chain 진행을 형성하는지 확인
            stage_indices = [_KILL_CHAIN_ORDER.index(s) for s in unique_stages]
            if stage_indices == sorted(stage_indices):
                incident = self._create_or_update_incident(
                    source, recent, "kill_chain", unique_stages
                )

        # 규칙 3: 버스트 탐지
        if len(self._alert_counts[source]) >= self._burst_threshold:
            if incident is None:
                incident = self._create_or_update_incident(
                    source, recent, "burst"
                )

        return incident

    def _create_or_update_incident(
        self,
        source: str,
        recent: deque[tuple[float, dict[str, Any]]],
        rule: str,
        stages: list[str] | None = None,
    ) -> Incident:
        """이 출발지에 대해 새 인시던트를 생성하거나 기존 인시던트를 업데이트한다."""
        # 이 출발지에 대한 미해결 인시던트가 있는지 확인
        for inc in reversed(self._incidents):
            if not inc.resolved and source in inc.source_ips:
                # 기존 인시던트 업데이트
                for _, info in recent:
                    if info.get("event_id") and info["event_id"] not in inc.alert_ids:
                        inc.alert_ids.append(info["event_id"])
                    inc.engines.add(info["engine"])
                if stages:
                    inc.kill_chain_stages = stages
                # 심각도를 최고 수준으로 업데이트
                for _, info in recent:
                    if info["severity"] > inc.severity:
                        inc.severity = info["severity"]
                inc.updated_at = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                )
                # DB에 업데이트 영속화
                self._persist_update(inc)
                return inc

        # 새 인시던트 생성
        alert_ids = [
            info["event_id"] for _, info in recent
            if info.get("event_id")
        ]
        engines = set(info["engine"] for _, info in recent)
        max_severity = max(
            (info["severity"] for _, info in recent),
            default=Severity.INFO,
        )

        if rule == "kill_chain" and stages:
            title = f"Kill Chain Activity from {source}"
            desc = (
                f"Multiple attack stages detected from {source}: "
                f"{' -> '.join(stages)}. "
                f"Engines triggered: {', '.join(sorted(engines))}."
            )
        elif rule == "burst":
            title = f"Alert Burst from {source}"
            desc = (
                f"{len(self._alert_counts[source])} alerts from {source} "
                f"in {self._burst_window}s."
            )
        else:
            title = f"Correlated Activity from {source}"
            desc = (
                f"Multiple detection engines triggered for {source}: "
                f"{', '.join(sorted(engines))}."
            )

        incident = Incident(
            id=self._next_id,
            severity=max_severity,
            title=title,
            description=desc,
            alert_ids=alert_ids,
            source_ips={source},
            engines=engines,
            kill_chain_stages=stages or [],
            rule=rule,
        )
        self._next_id += 1
        self._incidents.append(incident)

        # 인메모리 캐시를 100개 인시던트로 제한
        if len(self._incidents) > 100:
            self._incidents = self._incidents[-100:]

        # DB에 영속화
        self._persist_create(incident)

        logger.info(
            "Incident #%d created: %s (rule=%s, alerts=%d)",
            incident.id, incident.title, rule, len(incident.alert_ids),
        )

        return incident

    def _persist_create(self, incident: Incident) -> None:
        """새 인시던트를 DB에 영속화한다 (fire-and-forget)."""
        if self._incident_repo is None:
            return
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                self._incident_repo.insert(
                    severity=incident.severity.value,
                    title=incident.title,
                    description=incident.description,
                    alert_ids=incident.alert_ids,
                    source_ips=sorted(incident.source_ips),
                    engines=sorted(incident.engines),
                    kill_chain_stages=incident.kill_chain_stages,
                    rule=incident.rule,
                )
            )
        except RuntimeError:
            pass

    def _persist_update(self, incident: Incident) -> None:
        """인시던트 업데이트를 DB에 영속화한다 (fire-and-forget)."""
        if self._incident_repo is None:
            return
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                self._incident_repo.update(
                    incident_id=incident.id,
                    severity=incident.severity.value,
                    alert_ids=incident.alert_ids,
                    engines=sorted(incident.engines),
                    kill_chain_stages=incident.kill_chain_stages,
                )
            )
        except RuntimeError:
            pass

    def get_incidents(self, limit: int = 50, include_resolved: bool = False) -> list[dict]:
        """인메모리 캐시에서 최근 인시던트를 반환한다."""
        result = []
        for inc in reversed(self._incidents):
            if not include_resolved and inc.resolved:
                continue
            result.append(inc.to_dict())
            if len(result) >= limit:
                break
        return result

    def resolve_incident(self, incident_id: int) -> bool:
        """인시던트를 해결 완료로 표시한다."""
        for inc in self._incidents:
            if inc.id == incident_id:
                inc.resolved = True
                # DB에 해결 상태 영속화
                if self._incident_repo is not None:
                    import asyncio
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(
                            self._incident_repo.resolve(incident_id)
                        )
                    except RuntimeError:
                        pass
                return True
        return False

    def get_incident(self, incident_id: int) -> dict | None:
        """ID로 단일 인시던트를 조회하여 딕셔너리로 반환한다."""
        for inc in self._incidents:
            if inc.id == incident_id:
                return inc.to_dict()
        return None
