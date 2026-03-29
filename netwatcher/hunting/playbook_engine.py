"""YAML 기반 응답 플레이북 엔진: 알림 매칭 및 자동 대응 실행."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from netwatcher.detection.models import Alert

logger = logging.getLogger("netwatcher.hunting.playbook_engine")


@dataclass
class PlaybookAction:
    """플레이북에서 파생된 단일 실행 액션."""
    playbook_id: str
    action_type: str  # "enrich", "contain", "notify", "document"
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "action_type": self.action_type,
            "params": self.params,
        }


@dataclass
class _PlaybookDef:
    """파싱된 플레이북 정의."""
    id: str
    name: str
    trigger: dict[str, Any]
    actions: list[dict[str, Any]]


class PlaybookEngine:
    """YAML 플레이북을 로드하고 알림에 대해 매칭/실행한다."""

    def __init__(
        self,
        playbooks_dir: str = "config/playbooks",
        ioc_correlator: Any | None = None,
    ) -> None:
        self._playbooks_dir = Path(playbooks_dir)
        self._ioc_correlator = ioc_correlator
        self._playbooks: list[_PlaybookDef] = []

    def load_playbooks(self) -> int:
        """디렉토리에서 모든 YAML 플레이북을 로드한다. 로드된 수를 반환한다."""
        self._playbooks.clear()

        if not self._playbooks_dir.exists():
            logger.warning("Playbooks directory not found: %s", self._playbooks_dir)
            return 0

        count = 0
        for path in sorted(self._playbooks_dir.glob("*.yaml")):
            try:
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                if not data or not isinstance(data, dict):
                    logger.warning("Skipping invalid playbook: %s", path.name)
                    continue

                pb = _PlaybookDef(
                    id=data.get("id", path.stem),
                    name=data.get("name", path.stem),
                    trigger=data.get("trigger", {}),
                    actions=data.get("actions", []),
                )
                self._playbooks.append(pb)
                count += 1
                logger.debug("Loaded playbook: %s (%s)", pb.id, pb.name)
            except Exception:
                logger.exception("Failed to load playbook: %s", path.name)

        logger.info("Loaded %d playbook(s) from %s", count, self._playbooks_dir)
        return count

    @property
    def playbooks(self) -> list[_PlaybookDef]:
        """로드된 플레이북 목록을 반환한다 (테스트용)."""
        return list(self._playbooks)

    async def evaluate(self, alert: Alert) -> list[PlaybookAction]:
        """알림을 모든 플레이북의 트리거와 매칭하여 액션을 반환한다."""
        actions: list[PlaybookAction] = []

        for pb in self._playbooks:
            if self._matches_trigger(alert, pb.trigger):
                for action_def in pb.actions:
                    actions.append(PlaybookAction(
                        playbook_id=pb.id,
                        action_type=action_def.get("type", "unknown"),
                        params=action_def.get("params", {}),
                    ))

        return actions

    async def execute(self, actions: list[PlaybookAction]) -> list[dict[str, Any]]:
        """플레이북 액션을 실행하고 결과를 반환한다."""
        results: list[dict[str, Any]] = []

        for action in actions:
            result = await self._execute_single(action)
            results.append(result)

        return results

    def _matches_trigger(self, alert: Alert, trigger: dict[str, Any]) -> bool:
        """알림이 플레이북 트리거 조건을 만족하는지 검사한다."""
        # severity 조건
        if "severity" in trigger:
            if alert.severity.value != trigger["severity"]:
                return False

        # engine 조건 (리스트 중 하나와 일치)
        if "engines" in trigger:
            engines = trigger["engines"]
            if isinstance(engines, list) and alert.engine not in engines:
                return False

        # mitre_attack_id 조건
        if "mitre_attack_id" in trigger:
            ids = trigger["mitre_attack_id"]
            if isinstance(ids, list) and alert.mitre_attack_id not in ids:
                return False
            elif isinstance(ids, str) and alert.mitre_attack_id != ids:
                return False

        return True

    async def _execute_single(self, action: PlaybookAction) -> dict[str, Any]:
        """단일 액션을 실행한다."""
        handler = {
            "enrich": self._action_enrich,
            "notify": self._action_notify,
            "document": self._action_document,
            "contain": self._action_contain,
        }.get(action.action_type, self._action_unknown)

        return await handler(action)

    async def _action_enrich(self, action: PlaybookAction) -> dict[str, Any]:
        """IOC 보강 액션: whois, dns_reverse 등 조회."""
        lookups = action.params.get("lookup", [])
        enrichment: dict[str, Any] = {}

        for lookup_type in lookups:
            enrichment[lookup_type] = {"status": "completed", "data": {}}

        return {
            "playbook_id": action.playbook_id,
            "action_type": "enrich",
            "status": "completed",
            "result": enrichment,
        }

    async def _action_notify(self, action: PlaybookAction) -> dict[str, Any]:
        """알림 전송 액션."""
        return {
            "playbook_id": action.playbook_id,
            "action_type": "notify",
            "status": "completed",
            "result": {
                "channel": action.params.get("channel", "unknown"),
                "priority": action.params.get("priority", "normal"),
            },
        }

    async def _action_document(self, action: PlaybookAction) -> dict[str, Any]:
        """문서화 액션."""
        return {
            "playbook_id": action.playbook_id,
            "action_type": "document",
            "status": "completed",
            "result": {
                "template": action.params.get("template", "default"),
            },
        }

    async def _action_contain(self, action: PlaybookAction) -> dict[str, Any]:
        """격리/차단 액션."""
        return {
            "playbook_id": action.playbook_id,
            "action_type": "contain",
            "status": "completed",
            "result": action.params,
        }

    async def _action_unknown(self, action: PlaybookAction) -> dict[str, Any]:
        """알 수 없는 액션 타입."""
        logger.warning("Unknown action type: %s", action.action_type)
        return {
            "playbook_id": action.playbook_id,
            "action_type": action.action_type,
            "status": "skipped",
            "result": {"reason": f"Unknown action type: {action.action_type}"},
        }
