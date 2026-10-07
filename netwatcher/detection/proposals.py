"""설정 변경 제안 승인 큐 (PR 10).

계획서의 요구:

    "읽기 / 제안 / 승인 3 역할을 분리한다"
    "제안 전용 경로가 runtime·YAML·방화벽을 바꾸면 출시 중단이다"

PR 03 으로 AI 는 설정을 직접 바꾸지 못하게 했다. 그런데 그제안조차
처리할 방법이 없었다 — 이벤트로만 기록되고 되돌릴 수 없는 로그가 되었다.
이 모듈이 그 닫힌 루프를 완성한다.

설계 원칙
    1. **제안할 때 검증한다.** 스키마를 어기는 제안은 큐에 들어가지도 못한다.
    2. **승인 시에만 쓴다.** 반영 경로는 대시보드 설정 쓰기와 **동일**하다
       (reload_engine → YAML 기록). 다른 경로를 만들지 않는다.
       별도 경로가 생기면 그 경로가 검증과 권한을 우회하는 구멍이 된다.
    2b. **검증 대상은 승인하려는 변경이다.** 기존 설정의 방치된 키가
       모든 승인을 막아서는 안 된다 — 그건 경고로 드러낸다.
    3. **실패를 숨기지 않는다.** 적용에 실패하면 status=failed 로 남기고 사유를
       기록한다. 승인됐다는 사실만 남기면 실제로는 반영되지 않은 상태가 된다.
    4. **되돌릴 근거를 남긴다.** 승인 시점의 이전 설정을 before 에 저장한다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("netwatcher.detection.proposals")

STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_FAILED = "failed"

SOURCE_AI = "ai"
SOURCE_HUMAN = "human"


class ProposalError(RuntimeError):
    """제안 처리가 거부되었을 때."""

    def __init__(self, message: str, violations: list[Any] | None = None) -> None:
        super().__init__(message)
        self.violations = violations or []


@dataclass
class Decision:
    """승인/거절 결과."""

    proposal_id: int
    approved: bool
    applied: bool = False
    engine: str = ""
    params: dict = field(default_factory=dict)
    error: str | None = None
    violations: list = field(default_factory=list)
    # 승인 대상은 아니지만 함께 드러낼 기존 설정의 부적합 (차단하지 않는다)
    warnings: list = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.approved:
            return STATUS_REJECTED
        return STATUS_APPROVED if self.applied else STATUS_FAILED

    def as_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "status": self.status,
            "applied": self.applied,
            "engine": self.engine,
            "params": dict(self.params),
            "error": self.error,
            "violations": [v.as_dict() if hasattr(v, "as_dict") else str(v)
                           for v in self.violations],
            "warnings": [v.as_dict() if hasattr(v, "as_dict") else str(v)
                         for v in self.warnings],
        }


class ProposalService:
    """제안 접수 → 검증 → 승인/거절 → 검증된 경로로 적용."""

    def __init__(
        self,
        registry: Any,
        yaml_editor: Any,
        proposal_repo: Any = None,
    ) -> None:
        self._registry = registry
        self._yaml_editor = yaml_editor
        self._repo = proposal_repo
        self._replay_service = None

    def require_replay_validation(self, service):
        self._replay_service = service

    @property
    def validation_required(self):
        return self._replay_service is not None

    async def attach_validation(self, proposal_id, normal_run_id, attack_run_id, actor):
        if self._replay_service is None or self._repo is None:
            raise ProposalError("리플레이 검증 경로를 사용할 수 없습니다")
        row = await self._repo.get_by_id(proposal_id)
        if not row or row.get('status') != STATUS_PENDING:
            raise ProposalError("대기 중인 제안만 검증할 수 있습니다")
        validation = await self._validate_runs(row, normal_run_id, attack_run_id)
        validation['confirmed_by'] = actor[:100]
        if not await self._repo.attach_validation(proposal_id, validation):
            raise ProposalError("다른 사람이 먼저 결정했습니다")
        return validation

    async def _validate_runs(self, row, normal_id, attack_id):
        from netwatcher.detection.proposal_validation import validate_pair, ValidationError
        if self._current_config(row['engine']) != (row.get('before') or {}):
            raise ProposalError("제안 이후 설정이 변경되었습니다. 현재 설정으로 다시 제안하세요")
        try:
            return await validate_pair(self._replay_service, row, normal_id, attack_id)
        except ValidationError as error:
            raise ProposalError(str(error)) from error

    # ------------------------------------------------------------------
    # 제안
    # ------------------------------------------------------------------

    async def submit(
        self,
        engine: str,
        params: dict[str, Any],
        reason: str = "",
        source: str = SOURCE_HUMAN,
    ) -> int:
        """제안을 접수한다. 스키마를 어기면 큐에 넣지 않고 거부한다."""
        if not isinstance(params, dict) or not params:
            raise ProposalError("제안 파라미터가 비어 있거나 dict 가 아니다")

        schema = self._schema_for(engine)
        if schema is None:
            raise ProposalError(f"알 수 없는 엔진이거나 스키마가 없다: {engine}")

        # 부분 업데이트이므로 allow_partial=True. 선언되지 않은 키는 거부된다.
        from netwatcher.detection.validation import validate_engine_config

        violations = validate_engine_config(schema, params, allow_partial=True)
        if violations:
            raise ProposalError(
                f"제안이 스키마를 위반한다 ({len(violations)}건)", violations,
            )

        if self._repo is None:
            raise ProposalError("제안 저장소가 없다 (승인 큐를 쓸 수 없다)")

        # 되돌리기 근거로 현재 설정을 함께 남긴다
        before = self._current_config(engine)
        proposal_id = await self._repo.insert(
            engine=engine, params=dict(params), reason=reason,
            source=source, before=before,
        )
        logger.info(
            "설정 제안 접수 (id=%s, engine=%s, source=%s, params=%s)",
            proposal_id, engine, source, params,
        )
        return int(proposal_id)

    # ------------------------------------------------------------------
    # 결정
    # ------------------------------------------------------------------

    async def decide(
        self,
        proposal_id: int,
        approved: bool,
        decided_by: str = "system",
        note: str = "",
    ) -> Decision:
        """제안을 승인하거나 거절한다.

        승인 시에도 **여기서 다시 검증한다.** 접수 시점과 승인 시점 사이에
        다른 사람이 설정을 바꿀 수 있으므로, 그 사이 스키마를 어긴 값이
        섞여 있을 수 있다.
        """
        if self._repo is None:
            raise ProposalError("제안 저장소가 없다")

        row = await self._repo.get_by_id(proposal_id)
        if row is None:
            raise ProposalError(f"제안을 찾을 수 없다: id={proposal_id}")
        if row.get("status") != STATUS_PENDING:
            raise ProposalError(
                f"이미 결정된 제안이다 (status={row.get('status')})"
            )

        engine = row["engine"]
        params = dict(row["params"] or {})

        if not approved:
            await self._repo.decide(proposal_id, STATUS_REJECTED, decided_by, note)
            logger.info(
                "설정 제안 거절 (id=%s, engine=%s, by=%s)", proposal_id, engine, decided_by,
            )
            return Decision(
                proposal_id=proposal_id, approved=False, engine=engine, params=params,
            )

        schema = self._schema_for(engine)
        from netwatcher.detection.validation import validate_engine_config

        # 검증 대상은 **승인하려는 변경 자체**다.
        #
        # 병합 결과 전체를 검증하면 문제가 생긴다: 기존 YAML 파일에
        # 스키마에 없는 키(방치된 키)나 빠진 필드가 하나라도 있으면
        # 그 이후의 모든 승인이 거절된다. 제안자는 자신의 제안을 고칠 수 없고,
        # 큐가 사실상 영구히 막힌다.
        #
        # 따라서 규칙을 나눈다.
        #   - 제안(params) 위반  → 거부. 승인 대상이 스키마를 어기면 안 된다.
        #   - 기존 설정(before) 위반 → 경고로 노출하되 차단하지 않는다.
        #     그 문제를 고치는 것은 이 승인의 범위가 아니다.
        param_violations = validate_engine_config(
            schema, params, allow_partial=True,
        )
        if param_violations:
            await self._repo.decide(
                proposal_id, STATUS_REJECTED, decided_by,
                note or "승인 대상이 스키마를 위반",
            )
            raise ProposalError(
                f"승인 대상이 스키마를 위반한다 ({len(param_violations)}건)",
                param_violations,
            )

        if self.validation_required:
            validation = row.get('validation_runs') or {}
            if not validation.get('normal_run_id') or not validation.get('attack_run_id'):
                raise ProposalError("정상·공격 리플레이 검증 근거를 먼저 연결하세요")
            await self._validate_runs(row, validation['normal_run_id'], validation['attack_run_id'])

        before = dict(row.get("before") or {})
        drift = validate_engine_config(schema, {**before, **params})
        # drift 에 남는 항목은 before 쪽에서 온 것이다 (params 는 위에서 통과)
        existing_drift = [v for v in drift if v.key in before or v.code in ("V-001", "V-002")]

        ok = await self._repo.decide(proposal_id, STATUS_APPROVED, decided_by, note)
        if not ok:
            raise ProposalError("다른 사람이 먼저 결정했다")

        try:
            if self.validation_required and self._current_config(engine) != before:
                raise RuntimeError("검증 이후 설정이 변경되었습니다")
            applied = self._apply(engine, params)
        except Exception as exc:
            logger.exception("승인된 제안 적용 실패: id=%s", proposal_id)
            await self._repo.mark_applied(proposal_id, False, str(exc))
            return Decision(
                proposal_id=proposal_id, approved=True, applied=False,
                engine=engine, params=params, error=str(exc),
                warnings=existing_drift,
            )

        await self._repo.mark_applied(proposal_id, True)
        if existing_drift:
            logger.warning(
                "승인됨, 다만 기존 설정에 미선언 키/누락 필드가 남아 있다 "
                "(engine=%s, %d건)", engine, len(existing_drift),
            )
        logger.info(
            "설정 제안 승인·적용 (id=%s, engine=%s, params=%s, by=%s)",
            proposal_id, engine, params, decided_by,
        )
        return Decision(
            proposal_id=proposal_id, approved=True, applied=applied,
            engine=engine, params=params, warnings=existing_drift,
        )

    # ------------------------------------------------------------------
    # 조회
    # ------------------------------------------------------------------

    async def pending(self, limit: int = 50) -> list[dict]:
        if self._repo is None:
            return []
        return await self._repo.list_pending(limit=limit)

    async def list_all(self, limit: int = 50, status: str | None = None) -> list[dict]:
        if self._repo is None:
            return []
        return await self._repo.list_recent(limit=limit, status=status)

    async def pending_count(self) -> int:
        if self._repo is None:
            return 0
        return await self._repo.count_pending()

    # ------------------------------------------------------------------
    # 내부
    # ------------------------------------------------------------------

    def _schema_for(self, engine: str) -> dict | None:
        getter = getattr(self._registry, "get_engine_schema", None)
        if not callable(getter):
            return None
        schema = getter(engine)
        if not isinstance(schema, dict) or not schema:
            return None
        return schema

    def _current_config(self, engine: str) -> dict:
        if self._yaml_editor is None:
            return {}
        try:
            return dict(self._yaml_editor.get_engine_config(engine) or {})
        except Exception:
            logger.exception("현재 설정 조회 실패: %s", engine)
            return {}

    def _apply(self, engine: str, params: dict) -> bool:
        """검증을 통과한 설정을 런타임과 YAML 에 반영한다.

        대시보드 설정 쓰기(PUT /engines/{name}/config)와 **동일한 순서**를
        따른다: reload 먼저, 성공한 경우에만 YAML 기록.
        """
        if self._yaml_editor is None:
            raise RuntimeError("YAML 편집기를 사용할 수 없다")

        self._yaml_editor.ensure_writable()
        previous = self._current_config(engine)
        merged = {**previous, **params}
        ok, err, _warnings = self._registry.reload_engine(engine, merged)
        if not ok:
            # Registry는 생성 실패 시 기존 엔진을 유지한다. 재생성하면 학습을 잃는다.
            raise RuntimeError(err or "엔진 리로드 실패")
        try:
            self._yaml_editor.update_engine_config(engine, params)
        except Exception:
            restored, _, _ = self._registry.reload_engine(engine, previous)
            if not restored:
                raise RuntimeError("Configuration rollback failed")
            raise
        return True
