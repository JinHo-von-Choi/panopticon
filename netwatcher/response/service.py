"""독립 승인 대조와 영속 실행 의도를 사용하는 실행기 서비스."""

import asyncio
import logging

import asyncpg

from netwatcher.response.command import ExecutionCommand
from netwatcher.response.executor import ExecutionResult, ExpiringExecutionRequest
from netwatcher.response.lifecycle import LifecycleError
from netwatcher.storage.execution_claims import ExecutionClaims, command_hash, _time

logger = logging.getLogger(__name__)


class ExecutionService:
    def __init__(self, claims: ExecutionClaims, executor) -> None:
        if getattr(executor, "applies_to_os", False) and (
            executor.name != "iptables" or not getattr(executor, "kernel_expiry_verified", False)
            or not getattr(executor, "supports_absolute_expiry", False)
        ):
            raise ValueError("OS 실행에는 검증된 iptables 만료·절대 시각 계약이 필요합니다")
        self.claims = claims
        self.executor = executor

    async def __call__(self, command: ExecutionCommand) -> ExecutionResult:
        try:
            if command.operation != "verify":
                previous = await self.claims.prepare(command)
                if previous is not None:
                    return previous
            async with self.claims.db.pool.acquire() as conn, conn.transaction():
                action = await self.claims.validate(conn, command)
                if command.operation != "verify":
                    claim = await conn.fetchrow("""SELECT * FROM response_execution_claims
                        WHERE action_id=$1 AND operation=$2 FOR UPDATE""", command.action_id, command.operation)
                    if claim is None or claim["request_hash"] != command_hash(command) or claim["status"] != "prepared":
                        raise LifecycleError("실행 의도를 확인할 수 없습니다", 409)
                # 잠근 계정·장치의 버전이 적용 도중 바뀌지 않게 한다.
                await self.claims._audit(conn, command, "execution_started", {})
                method = getattr(self.executor, command.operation)
                request = ExpiringExecutionRequest(**command.request().__dict__,
                    expires_at=_time(action["expire_at"]) if action["expire_at"] else None)
                try:
                    result = await asyncio.to_thread(method, request)
                except Exception:
                    logger.exception("실행기 결과 미확정: action_id=%s operation=%s", command.action_id, command.operation)
                    result = ExecutionResult("error", "unknown", detail="실행 결과 대조가 필요합니다", backend=self.executor.name)
                await conn.execute("""INSERT INTO response_receipts(action_id,phase,outcome,detail)
                    VALUES($1,$2,$3,$4)""", command.action_id, command.operation, result.outcome, result.as_dict())
                if command.operation != "verify":
                    await conn.execute("""UPDATE response_execution_claims SET status='completed',result=$3,
                        completed_at=clock_timestamp() WHERE action_id=$1 AND operation=$2""",
                        command.action_id, command.operation, result.as_dict())
                    state = "active_verified" if command.operation == "apply" and result.verified else "unknown"
                    if command.operation == "remove" and result.outcome == "absent" and result.observed == "absent":
                        state = "removed_verified"
                    await conn.execute("""UPDATE response_actions SET state=$2,rule_tag=$3,
                        rule_fingerprint=COALESCE($4,rule_fingerprint),last_error=$5,updated_at=NOW() WHERE id=$1""",
                        command.action_id, state, f"nw-{command.action_id}", result.rule_fingerprint, result.detail or None)
                await self.claims._audit(conn, command, "execution_result", result.as_dict())
            return result
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, TimeoutError):
            raise LifecycleError("실행 상태를 저장·확인할 수 없습니다. 상태 대조가 필요합니다", 503) from None
