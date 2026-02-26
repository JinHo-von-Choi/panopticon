"""AIAnalyzerService — AI CLI 기반 오탐률 자동 감소 서비스.

주기적으로 CRITICAL/WARNING 이벤트를 배치 분석하여:
- CONFIRMED_THREAT: 알림 재전송 (rate limit 우회)
- FALSE_POSITIVE:   엔진 임계값 자동 상향 + 핫리로드
- UNCERTAIN:        로그 기록만

지원 프로바이더 (config ai_analyzer.provider):
  copilot  — gh copilot explain <prompt>    (기본값)
  claude   — claude -p <prompt>
  codex    — codex <prompt>
  gemini   — gemini <prompt>
  agent    — claude --agent <prompt>        (실험적)

작성자: 최진호
작성일: 2026-02-27
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.storage.repositories import EventRepository
    from netwatcher.utils.config import Config
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger("netwatcher.services.ai_analyzer")


@dataclass
class AnalysisResult:
    """Copilot 응답 파싱 결과."""

    verdict:     str              # CONFIRMED_THREAT | FALSE_POSITIVE | UNCERTAIN
    engine:      str              # 대상 엔진 이름
    reason:      str = ""
    adjustments: dict[str, float] = field(default_factory=dict)


class AIAnalyzerService:
    """AI CLI 기반 오탐률 자동 감소 서비스.

    config의 ``ai_analyzer.provider`` 값으로 CLI 백엔드를 선택한다.
    """

    # provider → CLI 커맨드 프리픽스. 프롬프트는 항상 마지막 인자로 추가된다.
    _PROVIDER_COMMANDS: dict[str, list[str]] = {
        "copilot": ["gh",     "copilot", "explain"],
        "claude":  ["claude", "-p"],
        "codex":   ["codex"],
        "gemini":  ["gemini"],
        "agent":   ["claude", "--agent"],
    }

    # ------------------------------------------------------------------ #
    # 파싱                                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_response(text: str) -> AnalysisResult:
        """Copilot 응답 텍스트에서 구조화된 결과를 추출한다.

        파싱 실패 시 verdict='UNCERTAIN', engine='' 를 반환한다.
        """
        upper = text.upper()

        # VERDICT — 단어 경계 매칭으로 오판 방지
        verdict = "UNCERTAIN"
        for candidate in ("CONFIRMED_THREAT", "FALSE_POSITIVE", "UNCERTAIN"):
            if re.search(rf"\b{candidate}\b", upper):
                verdict = candidate
                break

        # ENGINE
        engine = ""
        engine_match = re.search(r"(?i)^ENGINE:\s*(\S+)", text, re.MULTILINE)
        if engine_match:
            engine = engine_match.group(1).strip()

        # REASON
        reason = ""
        reason_match = re.search(r"(?i)^REASON:\s*(.+)", text, re.MULTILINE)
        if reason_match:
            reason = reason_match.group(1).strip()

        # ADJUST  (여러 줄 가능)
        adjustments: dict[str, float] = {}
        for m in re.finditer(r"(?i)^ADJUST:\s*(\w+)=([\d.]+)", text, re.MULTILINE):
            key, raw = m.group(1), m.group(2)
            try:
                adjustments[key] = float(raw)
            except ValueError:
                logger.warning("ADJUST 파싱 실패: %s=%s", key, raw)

        return AnalysisResult(
            verdict=verdict,
            engine=engine,
            reason=reason,
            adjustments=adjustments,
        )

    def __init__(
        self,
        config: "Config",
        event_repo: "EventRepository",
        registry: "EngineRegistry",
        dispatcher: "AlertDispatcher",
        yaml_editor: "YamlConfigEditor | None",
    ) -> None:
        """서비스 의존성을 주입받아 초기화한다."""
        ai_cfg = config.section("ai_analyzer") or {}

        self._config      = config
        self._event_repo  = event_repo
        self._registry    = registry
        self._dispatcher  = dispatcher
        self._yaml_editor = yaml_editor

        self._provider:         str = str(ai_cfg.get("provider", "copilot"))
        self._interval_seconds: int = int(ai_cfg.get("interval_minutes",  15)) * 60
        self._lookback_minutes: int = int(ai_cfg.get("lookback_minutes",  30))
        self._max_events:       int = int(ai_cfg.get("max_events",        50))
        self._fp_threshold:     int = int(ai_cfg.get("consecutive_fp_threshold", 2))
        self._max_pct:          int = int(ai_cfg.get("max_threshold_increase_pct", 20))
        self._timeout:          int = int(ai_cfg.get("copilot_timeout_seconds", 60))

        if self._provider not in self._PROVIDER_COMMANDS:
            logger.warning(
                "[ai_analyzer] 알 수 없는 프로바이더 '%s' — 'copilot'으로 폴백",
                self._provider,
            )
            self._provider = "copilot"

        self._consecutive_fp: dict[str, int]  = {}
        self._task: asyncio.Task | None        = None

    # ------------------------------------------------------------------ #
    # 임계값 자동 조정                                                       #
    # ------------------------------------------------------------------ #

    def _try_adjust_threshold(
        self, engine: str, adjustments: dict[str, float],
    ) -> None:
        """연속 오탐 카운터를 증가시키고, 임계값에 달하면 설정을 업데이트한다.

        - 연속 오탐 횟수가 fp_threshold 미만이면 카운터만 증가
        - 임계값 달성 시 cap 적용 후 YamlConfigEditor + registry.reload_engine()
        - yaml_editor가 None이면 WARNING 로그 후 skip
        """
        key = engine
        self._consecutive_fp[key] = self._consecutive_fp.get(key, 0) + 1

        if self._consecutive_fp[key] < self._fp_threshold:
            logger.info(
                "[ai_analyzer] %s 오탐 카운터 %d/%d",
                engine, self._consecutive_fp[key], self._fp_threshold,
            )
            return

        if self._yaml_editor is None:
            logger.warning("[ai_analyzer] yaml_editor 없음 — 임계값 조정 불가")
            return

        # 현재 엔진 설정 조회 및 cap 적용
        try:
            current_cfg = self._yaml_editor.get_engine_config(engine) or {}
        except Exception:
            logger.exception("[ai_analyzer] 엔진 설정 조회 실패: %s", engine)
            return

        capped: dict[str, float] = {}
        for param, requested in adjustments.items():
            current_val = current_cfg.get(param)
            if current_val is None or not isinstance(current_val, (int, float)):
                capped[param] = requested
                continue
            cap_val = current_val * (1 + self._max_pct / 100)
            capped[param] = min(requested, cap_val)

        try:
            self._yaml_editor.update_engine_config(engine, capped)
        except Exception:
            logger.exception("[ai_analyzer] config 업데이트 실패: %s", engine)
            return

        # 엔진 핫리로드
        new_cfg = self._yaml_editor.get_engine_config(engine) or {}
        ok, err, _ = self._registry.reload_engine(engine, new_cfg)
        if ok:
            logger.info("[ai_analyzer] 엔진 핫리로드 완료: %s %s", engine, capped)
        else:
            logger.error("[ai_analyzer] 엔진 핫리로드 실패: %s — %s", engine, err)

        self._consecutive_fp[key] = 0

    # ------------------------------------------------------------------ #
    # AI CLI 실행                                                           #
    # ------------------------------------------------------------------ #

    async def _run_ai(self, prompt: str) -> str:
        """설정된 AI 프로바이더 CLI를 서브프로세스로 실행하고 stdout을 반환한다.

        타임아웃, FileNotFoundError(CLI 미설치), 기타 예외 시 빈 문자열을 반환한다.
        """
        cmd = self._PROVIDER_COMMANDS[self._provider] + [prompt]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=float(self._timeout),
                )
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning(
                    "[ai_analyzer] %s CLI 타임아웃 (%ds)", self._provider, self._timeout,
                )
                return ""
            return stdout.decode("utf-8", errors="replace")
        except FileNotFoundError:
            logger.error(
                "[ai_analyzer] %s CLI를 찾을 수 없음 — 분석 불가", self._provider,
            )
            return ""
        except Exception:
            logger.exception("[ai_analyzer] %s 실행 오류", self._provider)
            return ""

    # ------------------------------------------------------------------ #
    # 프롬프트 구성                                                         #
    # ------------------------------------------------------------------ #

    def _build_prompt(self, events: list[dict]) -> str:
        """분석 대상 이벤트를 구조화된 Copilot 프롬프트로 변환한다."""
        slim = [
            {
                "engine":    e.get("engine", ""),
                "severity":  e.get("severity", ""),
                "title":     e.get("title", ""),
                "source_ip": str(e.get("source_ip", "")),
                "timestamp": str(e.get("timestamp", "")),
            }
            for e in events
        ]
        events_json = json.dumps(slim, ensure_ascii=False, indent=2)

        return (
            f"Analyze these network security alerts from a home/office LAN monitor "
            f"(lookback: {self._lookback_minutes} minutes). "
            f"Determine if they represent a real attack or a false positive. "
            f"ALERTS: {events_json} "
            f"Respond ONLY in this exact format: "
            f"VERDICT: CONFIRMED_THREAT | FALSE_POSITIVE | UNCERTAIN "
            f"ENGINE: <engine_name> "
            f"REASON: <one sentence> "
            f"ADJUST: <param>=<numeric_value> (only if FALSE_POSITIVE, can repeat)"
        )

    # ------------------------------------------------------------------ #
    # 분석 결과 적용                                                        #
    # ------------------------------------------------------------------ #

    async def _apply_result(self, result: AnalysisResult) -> None:
        """파싱된 분석 결과에 따라 알림 재전송 또는 임계값 조정을 수행한다."""
        if result.verdict == "CONFIRMED_THREAT":
            from netwatcher.detection.models import Alert, Severity
            alert = Alert(
                engine="ai_analyzer",
                severity=Severity.CRITICAL,
                title=f"[AI 확인] {result.engine} — 실제 위협",
                description=result.reason,
                confidence=1.0,
                metadata={"ai_confirmed": True, "original_engine": result.engine},
            )
            self._dispatcher.enqueue(alert)
            logger.warning(
                "[ai_analyzer] CONFIRMED_THREAT: engine=%s reason=%s",
                result.engine, result.reason,
            )

        elif result.verdict == "FALSE_POSITIVE":
            logger.info(
                "[ai_analyzer] FALSE_POSITIVE: engine=%s adjustments=%s",
                result.engine, result.adjustments,
            )
            self._try_adjust_threshold(result.engine, result.adjustments)

        else:  # UNCERTAIN
            logger.info(
                "[ai_analyzer] UNCERTAIN: engine=%s reason=%s",
                result.engine, result.reason,
            )

    # ------------------------------------------------------------------ #
    # 이벤트 조회                                                           #
    # ------------------------------------------------------------------ #

    async def _fetch_recent_events(self) -> list[dict]:
        """최근 lookback_minutes 내 CRITICAL/WARNING 이벤트를 조회한다.

        EventRepository.list_recent()가 단일 severity만 지원하므로 두 번 호출 후 병합한다.
        """
        from datetime import datetime, timedelta, timezone
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=self._lookback_minutes)
        ).isoformat()

        half = self._max_events // 2
        try:
            criticals = await self._event_repo.list_recent(
                severity="CRITICAL", since=since, limit=half,
            )
            warnings = await self._event_repo.list_recent(
                severity="WARNING", since=since, limit=half,
            )
        except Exception:
            logger.exception("[ai_analyzer] 이벤트 조회 실패")
            return []

        merged = criticals + warnings
        merged.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
        return merged[: self._max_events]

    # ------------------------------------------------------------------ #
    # 분석 루프                                                            #
    # ------------------------------------------------------------------ #

    async def _run_once(self) -> None:
        """단일 분석 사이클: 이벤트 조회 → AI CLI 실행 → 결과 적용."""
        events = await self._fetch_recent_events()
        if not events:
            logger.debug("[ai_analyzer] 분석 대상 이벤트 없음")
            return

        prompt = self._build_prompt(events)
        raw    = await self._run_ai(prompt)
        if not raw:
            return

        result = self._parse_response(raw)
        logger.info(
            "[ai_analyzer] 분석 완료: verdict=%s engine=%s",
            result.verdict, result.engine,
        )
        await self._apply_result(result)

    async def _analysis_loop(self) -> None:
        """interval_seconds마다 _run_once()를 호출하는 백그라운드 루프."""
        logger.info("[ai_analyzer] 분석 루프 시작 (interval=%ds)", self._interval_seconds)
        while True:
            try:
                await self._run_once()
            except Exception:
                logger.exception("[ai_analyzer] 분석 루프 오류")
            await asyncio.sleep(self._interval_seconds)

    # ------------------------------------------------------------------ #
    # 라이프사이클                                                          #
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """백그라운드 분석 루프를 시작한다."""
        self._task = asyncio.create_task(self._analysis_loop())
        logger.info("AIAnalyzerService started")

    async def stop(self) -> None:
        """백그라운드 루프를 취소하고 정리한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("AIAnalyzerService stopped")
