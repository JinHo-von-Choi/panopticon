"""Elastic Common Schema (ECS) 필드 매퍼.

Alert 객체를 ECS 호환 딕셔너리로 변환한다.
참조: https://www.elastic.co/guide/en/ecs/current/index.html
"""

from __future__ import annotations

import os
import socket
from typing import Any

from netwatcher.detection.attack_mapping import get_ttp
from netwatcher.detection.models import Alert, Severity

# 심각도 -> ECS event.severity 숫자 매핑 (syslog 기반)
_SEVERITY_MAP: dict[Severity, int] = {
    Severity.CRITICAL: 1,
    Severity.WARNING:  3,
    Severity.INFO:     6,
}

_HOSTNAME = socket.gethostname()
_PID      = str(os.getpid())


def alert_to_ecs(alert: Alert) -> dict[str, Any]:
    """Alert를 ECS 호환 딕셔너리로 매핑한다."""
    doc: dict[str, Any] = {
        "@timestamp":  alert.timestamp,
        "message":     alert.title,
        "event": {
            "kind":     "alert",
            "category":  ["intrusion_detection"],
            "severity":  _SEVERITY_MAP.get(alert.severity, 6),
            "reason":    alert.description,
            "module":    "netwatcher",
            "dataset":   f"netwatcher.{alert.engine}",
        },
        "rule": {
            "name": alert.engine,
        },
        "host": {
            "hostname": _HOSTNAME,
        },
        "process": {
            "pid": _PID,
        },
        "netwatcher": {
            "confidence":  alert.confidence,
            "threat_level": alert.threat_level,
            "metadata":    alert.metadata,
        },
    }

    if alert.source_ip:
        doc["source"] = {"ip": alert.source_ip}
    if alert.source_mac:
        doc.setdefault("source", {})["mac"] = alert.source_mac

    if alert.dest_ip:
        doc["destination"] = {"ip": alert.dest_ip}
    if alert.dest_mac:
        doc.setdefault("destination", {})["mac"] = alert.dest_mac

    if alert.mitre_attack_id:
        technique: dict[str, Any] = {"id": alert.mitre_attack_id}
        ttp = get_ttp(alert.mitre_attack_id)
        if ttp:
            technique["name"]      = ttp.name
            technique["reference"] = f"https://attack.mitre.org/techniques/{ttp.id.replace('.', '/')}/"
            doc["threat"] = {
                "framework": "MITRE ATT&CK",
                "technique": [technique],
                "tactic": {
                    "name": ttp.tactic,
                },
            }
        else:
            doc["threat"] = {
                "framework": "MITRE ATT&CK",
                "technique": [technique],
            }

    return doc
