"""STIX 2.1 번들 생성 및 TAXII 2.1 클라이언트.

Alert 객체를 STIX Indicator + Sighting 으로 변환하고,
선택적으로 TAXII 2.1 서버에 POST 한다.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import aiohttp

from netwatcher.alerts.channels.base import NotificationChannel
from netwatcher.detection.attack_mapping import get_ttp
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.integrations.stix")

_NETWATCHER_IDENTITY_ID = "identity--a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


def _deterministic_uuid(namespace: str, key: str) -> str:
    """네임스페이스 + 키로 결정적 UUID v5를 생성한다."""
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
    return str(uuid.uuid5(ns, f"{namespace}:{key}"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def alert_to_indicator(alert: Alert) -> dict[str, Any]:
    """Alert를 STIX 2.1 Indicator 객체로 변환한다."""
    indicator_id = f"indicator--{_deterministic_uuid('netwatcher-indicator', alert.rate_limit_key)}"

    pattern_parts: list[str] = []
    if alert.source_ip:
        pattern_parts.append(f"[ipv4-addr:value = '{alert.source_ip}']")
    if alert.dest_ip:
        pattern_parts.append(f"[ipv4-addr:value = '{alert.dest_ip}']")
    if not pattern_parts:
        pattern_parts.append("[artifact:payload_bin = 'unknown']")

    pattern = " OR ".join(pattern_parts)

    indicator: dict[str, Any] = {
        "type":           "indicator",
        "spec_version":   "2.1",
        "id":             indicator_id,
        "created":        alert.timestamp,
        "modified":       alert.timestamp,
        "name":           alert.title,
        "description":    alert.description,
        "indicator_types": [_severity_to_indicator_type(alert.severity)],
        "pattern":        pattern,
        "pattern_type":   "stix",
        "valid_from":     alert.timestamp,
        "confidence":     int(alert.confidence * 100),
        "created_by_ref": _NETWATCHER_IDENTITY_ID,
    }

    if alert.mitre_attack_id:
        indicator["kill_chain_phases"] = _build_kill_chain_phases(alert.mitre_attack_id)
        indicator["external_references"] = _build_external_references(alert.mitre_attack_id)

    return indicator


def alert_to_sighting(alert: Alert, indicator_id: str) -> dict[str, Any]:
    """Alert를 STIX 2.1 Sighting 객체로 변환한다."""
    sighting_id = f"sighting--{_deterministic_uuid('netwatcher-sighting', f'{alert.rate_limit_key}:{alert.timestamp}')}"

    sighting: dict[str, Any] = {
        "type":            "sighting",
        "spec_version":    "2.1",
        "id":              sighting_id,
        "created":         alert.timestamp,
        "modified":        alert.timestamp,
        "first_seen":      alert.timestamp,
        "last_seen":       alert.timestamp,
        "count":           1,
        "sighting_of_ref": indicator_id,
        "created_by_ref":  _NETWATCHER_IDENTITY_ID,
    }

    observed: list[dict[str, Any]] = []
    if alert.source_ip:
        observed.append({
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": f"ipv4-addr--{_deterministic_uuid('ipv4', alert.source_ip)}",
            "value": alert.source_ip,
        })
    if alert.dest_ip:
        observed.append({
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": f"ipv4-addr--{_deterministic_uuid('ipv4', alert.dest_ip)}",
            "value": alert.dest_ip,
        })

    if observed:
        sighting["observed_data_refs"] = [o["id"] for o in observed]

    return sighting


def _netwatcher_identity() -> dict[str, Any]:
    """NetWatcher STIX Identity 객체를 반환한다."""
    return {
        "type":         "identity",
        "spec_version": "2.1",
        "id":           _NETWATCHER_IDENTITY_ID,
        "created":      "2025-01-01T00:00:00.000Z",
        "modified":     "2025-01-01T00:00:00.000Z",
        "name":         "NetWatcher IDS",
        "identity_class": "system",
    }


def build_stix_bundle(alert: Alert) -> dict[str, Any]:
    """Alert로부터 완전한 STIX 2.1 Bundle을 생성한다."""
    indicator    = alert_to_indicator(alert)
    sighting     = alert_to_sighting(alert, indicator["id"])
    identity     = _netwatcher_identity()

    objects: list[dict[str, Any]] = [identity, indicator, sighting]

    # MITRE ATT&CK attack-pattern 참조 추가
    if alert.mitre_attack_id:
        attack_pattern = _build_attack_pattern(alert.mitre_attack_id)
        if attack_pattern:
            objects.append(attack_pattern)
            # Indicator -> attack-pattern 관계
            objects.append({
                "type":            "relationship",
                "spec_version":    "2.1",
                "id":              "relationship--" + _deterministic_uuid("rel", indicator["id"] + ":" + attack_pattern["id"]),
                "created":         alert.timestamp,
                "modified":        alert.timestamp,
                "relationship_type": "indicates",
                "source_ref":      indicator["id"],
                "target_ref":      attack_pattern["id"],
            })

    bundle_id = f"bundle--{uuid.uuid4()}"
    return {
        "type":         "bundle",
        "id":           bundle_id,
        "objects":      objects,
    }


def _severity_to_indicator_type(severity: Severity) -> str:
    """심각도를 STIX indicator type으로 매핑한다."""
    mapping = {
        Severity.CRITICAL: "malicious-activity",
        Severity.WARNING:  "anomalous-activity",
        Severity.INFO:     "benign",
    }
    return mapping.get(severity, "unknown")


def _build_kill_chain_phases(mitre_id: str) -> list[dict[str, str]]:
    """MITRE ATT&CK ID를 STIX kill_chain_phases 형식으로 변환한다."""
    ttp = get_ttp(mitre_id)
    if not ttp:
        return []
    return [{
        "kill_chain_name": "mitre-attack",
        "phase_name":      ttp.tactic,
    }]


def _build_external_references(mitre_id: str) -> list[dict[str, str]]:
    """MITRE ATT&CK 외부 참조를 생성한다."""
    ttp = get_ttp(mitre_id)
    ref: dict[str, str] = {
        "source_name": "mitre-attack",
        "external_id": mitre_id,
        "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
    }
    if ttp:
        ref["description"] = ttp.name
    return [ref]


def _build_attack_pattern(mitre_id: str) -> dict[str, Any] | None:
    """MITRE ATT&CK ID를 STIX attack-pattern 객체로 변환한다."""
    ttp = get_ttp(mitre_id)
    if not ttp:
        return None

    return {
        "type":         "attack-pattern",
        "spec_version": "2.1",
        "id":           f"attack-pattern--{_deterministic_uuid('mitre', mitre_id)}",
        "created":      "2025-01-01T00:00:00.000Z",
        "modified":     "2025-01-01T00:00:00.000Z",
        "name":         ttp.name,
        "description":  ttp.description,
        "kill_chain_phases": [{
            "kill_chain_name": "mitre-attack",
            "phase_name":      ttp.tactic,
        }],
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": mitre_id,
            "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
        }],
    }


class StixTaxiiChannel(NotificationChannel):
    """STIX 번들을 생성하고 TAXII 2.1 서버에 전송하는 채널."""

    name = "stix_taxii"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._taxii_url     = config.get("taxii_url", "")
        self._collection_id = config.get("collection_id", "")
        self._api_key       = config.get("api_key", "")

    async def send(self, alert: Alert) -> bool:
        """Alert를 STIX 번들로 변환하고 TAXII 서버에 전송한다."""
        bundle = build_stix_bundle(alert)

        if not self._taxii_url or not self._collection_id:
            logger.debug("TAXII 미설정, STIX 번들 생성만 수행: %s", bundle["id"])
            return True

        return await self._post_to_taxii(bundle)

    async def _post_to_taxii(self, bundle: dict[str, Any]) -> bool:
        """TAXII 2.1 서버의 collection에 번들을 POST한다."""
        url = f"{self._taxii_url.rstrip('/')}/collections/{self._collection_id}/objects/"

        headers: dict[str, str] = {
            "Content-Type": "application/taxii+json;version=2.1",
            "Accept":       "application/taxii+json;version=2.1",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=bundle,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status in (200, 201, 202):
                        logger.debug("TAXII 전송 성공: %s", bundle["id"])
                        return True
                    else:
                        text = await resp.text()
                        logger.error(
                            "TAXII 전송 실패: %d - %s", resp.status, text[:500]
                        )
                        return False
        except Exception:
            logger.exception("TAXII 전송 오류")
            return False
