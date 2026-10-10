"""분리 콘솔에서 AI 분석을 실행한다.

분석과 공급자 호출(API 키 포함)은 권한 없는 콘솔 프로세스에서 한다. 센서에는 지정한 분석가 계정
(``ai_analyzer.service_account``)으로 엔진 조회와 설정 제안만 요청한다. 그 계정이 할 수 없는 일은
분석기도 할 수 없다. 판정 경보는 사건 테이블에 직접 기록한다.
"""

from __future__ import annotations

import logging

from netwatcher.services.ai_analyzer import AIAnalyzerService
from netwatcher.services.sensor_control import SensorControlError

logger = logging.getLogger("netwatcher.services.console_ai")

_TYPES = {"int": int, "float": float, "bool": bool, "str": str, "list": list, "dict": dict}
_SERVICE_ROLES = {"analyst", "admin"}


class RemoteEngineView:
    """센서에서 읽은 엔진 상태를 분석기의 레지스트리·설정 편집기 자리에 둔다."""

    def __init__(self):
        self._states: dict[str, dict] = {}

    def remember(self, engine: str, state: dict) -> None:
        self._states[engine] = state

    def forget(self, engine: str) -> None:
        self._states.pop(engine, None)

    def base_version(self, engine: str) -> str | None:
        state = self._states.get(engine)
        return state["base_version"] if state else None

    def get_engine_config(self, engine: str):
        state = self._states.get(engine)
        config = state["engine"].get("config") if state else None
        return dict(config) if isinstance(config, dict) else None

    def get_engine_schema(self, engine: str):
        state = self._states.get(engine)
        fields = state["engine"].get("schema") if state else None
        if not isinstance(fields, list):
            return None
        return {field["key"]: (_TYPES.get(field.get("type"), str), field.get("default"))
                for field in fields if isinstance(field, dict) and isinstance(field.get("key"), str)}


class EventAlertSink:
    """경보 디스패처 대신 사건 테이블에 판정 경보를 기록한다."""

    def __init__(self, event_repo, spawn):
        self.event_repo, self.spawn = event_repo, spawn

    def enqueue(self, alert) -> None:
        self.spawn(self.event_repo.insert(
            engine=alert.engine, severity=alert.severity.value, title=alert.title,
            title_key=alert.title_key, description=alert.description, metadata=alert.metadata))


class RemoteProposals:
    """분석가 계정으로 센서에 설정 제안을 낸다. 분석 때 본 설정이 바뀌었으면 센서가 거절한다."""

    def __init__(self, control, view: RemoteEngineView, provider: str):
        self.control, self.view, self.provider = control, view, provider
        self.actor = None

    async def submit(self, engine, params, reason="", source=None, expected_config=None):
        from netwatcher.detection.proposals import ProposalError
        base = self.view.base_version(engine)
        if self.actor is None or base is None or expected_config is None:
            raise ProposalError("센서 엔진 상태를 확인하지 못해 제안하지 않습니다")
        try:
            result = await self.control.proposals(
                "proposal.submit", self.actor, engine=engine, base_version=base,
                updates={"params": dict(params), "reason": f"[AI {self.provider}] {reason}"[:2000]})
        except SensorControlError as error:
            raise ProposalError(f"센서가 제안을 거절했습니다 ({error.code})") from None
        return int(result["proposal"]["id"])


class ConsoleAIAnalyzer(AIAnalyzerService):
    def __init__(self, config, event_repo, control, accounts):
        ai_cfg = config.section("ai_analyzer") or {}
        account = ai_cfg.get("service_account")
        if not isinstance(account, str) or not account:
            raise ValueError("ai_analyzer.service_account is required when the console runs AI analysis")
        self._view = RemoteEngineView()
        self._remote_proposals = RemoteProposals(control, self._view, str(ai_cfg.get("provider", "")))
        super().__init__(config, event_repo, registry=self._view, dispatcher=EventAlertSink(event_repo, self._spawn),
                         yaml_editor=self._view, whitelist=None, proposal_service=self._remote_proposals)
        self._control, self._accounts, self._account = control, accounts, account

    async def _actor(self) -> dict:
        """계정 권한·비활성·비밀번호 변경을 매번 다시 읽는다."""
        account = await self._accounts.get_by_username(self._account)
        if account is None or not account["enabled"] or account["role"] not in _SERVICE_ROLES:
            raise PermissionError("ai_analyzer.service_account must be an enabled analyst or admin account")
        return {"uid": str(account["id"]), "ver": account["version"], "sub": account["username"],
                "role": account["role"]}

    async def _apply_result(self, result) -> None:
        try:
            actor = await self._actor()
        except PermissionError as error:
            self._fail("service_account")
            logger.error("[ai_analyzer] %s", error)
            return
        self._remote_proposals.actor = actor
        if result.engine:
            try:
                self._view.remember(result.engine, await self._control.read(result.engine, actor))
            except SensorControlError as error:
                # 없는 엔진이거나 센서에 닿지 못하면 판정만 남기고 제안은 만들지 않는다.
                self._view.forget(result.engine)
                logger.warning("[ai_analyzer] 엔진 상태 조회 실패 (%s, %s)", result.engine, error.code)
        await super()._apply_result(result)
