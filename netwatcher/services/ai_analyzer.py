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
    from netwatcher.detection.whitelist import Whitelist
    from netwatcher.storage.repositories import EventRepository
    from netwatcher.utils.config import Config
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger("netwatcher.services.ai_analyzer")


@dataclass
class AnalysisResult:
    """AI CLI 응답 파싱 결과."""

    verdict:     str              # CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | UNCERTAIN
    engine:      str              # 대상 엔진 이름
    reason:      str = ""
    reasoning:   str = ""         # 번호 목록 형식 판단 근거
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
        "gemini":  ["gemini", "-p"],
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

        # VERDICT — 단어 경계 매칭으로 오판 방지. MISSED_THREAT 추가
        verdict = "UNCERTAIN"
        for candidate in ("CONFIRMED_THREAT", "FALSE_POSITIVE", "MISSED_THREAT", "UNCERTAIN"):
            if re.search(rf"\b{candidate}\b", upper):
                verdict = candidate
                break

        # ENGINE
        engine = ""
        engine_match = re.search(r"(?i)^ENGINE:\s*(\S+)", text, re.MULTILINE)
        if engine_match:
            engine = engine_match.group(1).strip()

        # REASON (한 줄)
        reason = ""
        reason_match = re.search(r"(?i)^REASON:\s*(.+)", text, re.MULTILINE)
        if reason_match:
            reason = reason_match.group(1).strip()

        # REASONING (번호 목록 블록 — ADJUST: 또는 끝까지)
        reasoning = ""
        reasoning_match = re.search(
            r"(?i)^REASONING:\s*\n((?:.*\n?)*?)(?=(?:ADJUST:|$))",
            text,
            re.MULTILINE,
        )
        if reasoning_match:
            reasoning = reasoning_match.group(1).strip()

        # ADJUST (여러 줄 가능)
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
            reasoning=reasoning,
            adjustments=adjustments,
        )

    def __init__(
        self,
        config: "Config",
        event_repo: "EventRepository",
        registry: "EngineRegistry",
        dispatcher: "AlertDispatcher",
        yaml_editor: "YamlConfigEditor | None",
        whitelist: "Whitelist | None" = None,
    ) -> None:
        """서비스 의존성을 주입받아 초기화한다."""
        ai_cfg = config.section("ai_analyzer") or {}

        self._config      = config
        self._event_repo  = event_repo
        self._registry    = registry
        self._dispatcher  = dispatcher
        self._yaml_editor = yaml_editor
        self._whitelist   = whitelist

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

        self._mt_threshold:    int = int(ai_cfg.get("consecutive_mt_threshold",    2))
        self._max_decrease_pct: int = int(ai_cfg.get("max_threshold_decrease_pct", 10))

        self._consecutive_fp: dict[str, int] = {}
        self._consecutive_mt: dict[str, int] = {}
        self._task: asyncio.Task | None       = None

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

        # 조정 이력 저장 (동기 컨텍스트 → asyncio.create_task로 비동기 예약)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            asyncio.create_task(
                self._event_repo.insert(
                    engine="ai_adjustment",
                    severity="INFO",
                    title=f"[AI 조정] {engine} 임계값 자동 상향",
                    description=str(capped),
                    metadata={
                        "engine": engine,
                        "adjusted": capped,
                        "provider": self._provider,
                    },
                )
            )

    def _try_lower_threshold(
        self, engine: str, adjustments: dict[str, float],
    ) -> None:
        """연속 미탐 카운터를 증가시키고, 임계값에 달하면 설정을 하향한다.

        - 연속 미탐 횟수가 mt_threshold 미만이면 카운터만 증가
        - 임계값 달성 시 cap 적용 후 YamlConfigEditor + registry.reload_engine()
        - cap 방향: max(requested, current * (1 - pct/100)) — 너무 급격한 하향 방지
        - yaml_editor가 None이면 WARNING 로그 후 skip
        """
        key = engine
        self._consecutive_mt[key] = self._consecutive_mt.get(key, 0) + 1

        if self._consecutive_mt[key] < self._mt_threshold:
            logger.info(
                "[ai_analyzer] %s 미탐 카운터 %d/%d",
                engine, self._consecutive_mt[key], self._mt_threshold,
            )
            return

        if self._yaml_editor is None:
            logger.warning("[ai_analyzer] yaml_editor 없음 — 임계값 하향 불가")
            return

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
            # 너무 급격한 하향 방지: requested와 cap 중 큰 값 선택
            cap_val = current_val * (1 - self._max_decrease_pct / 100)
            capped[param] = max(requested, cap_val)

        try:
            self._yaml_editor.update_engine_config(engine, capped)
        except Exception:
            logger.exception("[ai_analyzer] config 하향 업데이트 실패: %s", engine)
            return

        new_cfg = self._yaml_editor.get_engine_config(engine) or {}
        ok, err, _ = self._registry.reload_engine(engine, new_cfg)
        if ok:
            logger.info("[ai_analyzer] 엔진 민감도 하향 완료: %s %s", engine, capped)
        else:
            logger.error("[ai_analyzer] 엔진 핫리로드 실패: %s — %s", engine, err)

        self._consecutive_mt[key] = 0

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            asyncio.create_task(
                self._event_repo.insert(
                    engine="ai_adjustment",
                    severity="WARNING",
                    title=f"[AI 미탐조정] {engine} 임계값 자동 하향",
                    description=str(capped),
                    metadata={
                        "engine": engine,
                        "adjusted": capped,
                        "provider": self._provider,
                    },
                )
            )

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
        
        # 기본 언어 설정 가져오기
        lang = self._config.get("netwatcher.language.default", "ko")
        lang_instruction = f"Respond in Korean." if lang == "ko" else "Respond in English."

        # 화이트리스트 문맥 정보 구성
        whitelist_info = ""
        if self._whitelist:
            wl = self._whitelist.to_dict()
            whitelist_info = (
                f"\nWHITELIST CONTEXT:\n"
                f"- IPs: {', '.join(wl.get('ips', [])) or 'None'}\n"
                f"- IP Ranges: {', '.join(wl.get('ip_ranges', [])) or 'None'}\n"
                f"- MACs: {', '.join(wl.get('macs', [])) or 'None'}\n"
                f"- Domains: {', '.join(wl.get('domains', [])) or 'None'}\n"
                f"- Domain Suffixes: {', '.join(wl.get('domain_suffixes', [])) or 'None'}\n"
                f"Trusted entities in the whitelist should be treated as very likely FALSE POSITIVES unless their behavior is clearly malicious."
            )

        return (
            f"Analyze these network security events from a home/office LAN monitor "
            f"(lookback: {self._lookback_minutes} minutes). {lang_instruction} "
            f"Note: This is a private home/office environment where some local scanning (printers, NAS) may occur. "
            f"{whitelist_info} "
            f"Events include CRITICAL, WARNING, and INFO severity levels. "
            f"Perform TWO checks: "
            f"(1) Are any CRITICAL/WARNING alerts actually false positives? "
            f"(2) Do any INFO/low-confidence events indicate a more serious missed threat? "
            f"Return the single most important finding. "
            f"EVENTS: {events_json} "
            f"Respond ONLY in this exact format: "
            f"VERDICT: CONFIRMED_THREAT | FALSE_POSITIVE | MISSED_THREAT | UNCERTAIN "
            f"ENGINE: <engine_name> "
            f"REASON: <one sentence in {('Korean' if lang == 'ko' else 'English')}> "
            f"REASONING: "
            f"1. <reason 1 in {('Korean' if lang == 'ko' else 'English')}> "
            f"2. <reason 2> "
            f"3. <reason 3> "
            f"ADJUST: <param>=<numeric_value> (FALSE_POSITIVE: raise value, MISSED_THREAT: lower value, can repeat)"
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
                title_key="ai_analyzer.verdicts.confirmed.title",
                description=result.reason,
                confidence=1.0,
                metadata={"ai_confirmed": True, "original_engine": result.engine, "engine_name": result.engine},
            )
            self._dispatcher.enqueue(alert)
            await self._event_repo.insert(
                engine="ai_analyzer",
                severity="CRITICAL",
                title=f"[AI 확인] {result.engine} — 실제 위협",
                title_key="ai_analyzer.verdicts.confirmed.title",
                description=result.reason,
                reasoning=result.reasoning or None,
                metadata={
                    "verdict": "CONFIRMED_THREAT",
                    "original_engine": result.engine,
                    "engine_name": result.engine,
                    "provider": self._provider,
                },
            )
            logger.warning(
                "[ai_analyzer] CONFIRMED_THREAT: engine=%s reason=%s",
                result.engine, result.reason,
            )

        elif result.verdict == "FALSE_POSITIVE":
            logger.info(
                "[ai_analyzer] FALSE_POSITIVE: engine=%s adjustments=%s",
                result.engine, result.adjustments,
            )
            await self._event_repo.insert(
                engine="ai_analyzer",
                severity="WARNING",
                title=f"[AI 오탐] {result.engine} — 오탐 판정",
                title_key="ai_analyzer.verdicts.false_positive.title",
                description=result.reason,
                reasoning=result.reasoning or None,
                metadata={
                    "verdict": "FALSE_POSITIVE",
                    "original_engine": result.engine,
                    "engine_name": result.engine,
                    "adjustments": result.adjustments,
                    "provider": self._provider,
                },
            )
            self._try_adjust_threshold(result.engine, result.adjustments)

        elif result.verdict == "MISSED_THREAT":
            from netwatcher.detection.models import Alert, Severity
            alert = Alert(
                engine="ai_analyzer",
                severity=Severity.CRITICAL,
                title=f"[AI 미탐] {result.engine} — 탐지 누락 의심",
                title_key="ai_analyzer.verdicts.missed_threat.title",
                description=result.reason,
                confidence=0.8,
                metadata={"missed_threat": True, "original_engine": result.engine, "engine_name": result.engine},
            )
            self._dispatcher.enqueue(alert)
            await self._event_repo.insert(
                engine="ai_analyzer",
                severity="CRITICAL",
                title=f"[AI 미탐] {result.engine} — 탐지 누락 의심",
                title_key="ai_analyzer.verdicts.missed_threat.title",
                description=result.reason,
                reasoning=result.reasoning or None,
                metadata={
                    "verdict": "MISSED_THREAT",
                    "original_engine": result.engine,
                    "engine_name": result.engine,
                    "provider": self._provider,
                },
            )
            logger.warning(
                "[ai_analyzer] MISSED_THREAT: engine=%s reason=%s",
                result.engine, result.reason,
            )
            self._try_lower_threshold(result.engine, result.adjustments)

        else:  # UNCERTAIN
            logger.info(
                "[ai_analyzer] UNCERTAIN: engine=%s reason=%s",
                result.engine, result.reason,
            )
            await self._event_repo.insert(
                engine="ai_analyzer",
                severity="INFO",
                title=f"[AI 불확실] {result.engine} — 판단 불가",
                title_key="ai_analyzer.verdicts.uncertain.title",
                description=result.reason,
                reasoning=result.reasoning or None,
                metadata={
                    "verdict": "UNCERTAIN",
                    "original_engine": result.engine,
                    "engine_name": result.engine,
                    "provider": self._provider,
                },
            )

    # ------------------------------------------------------------------ #
    # 이벤트 조회                                                           #
    # ------------------------------------------------------------------ #

    async def _fetch_recent_events(self) -> list[dict]:
        """최근 lookback_minutes 내 CRITICAL/WARNING/INFO 이벤트를 조회한다.

        CRITICAL + WARNING은 각 max_events // 2개, INFO는 max_events // 3개.
        """
        from datetime import datetime, timedelta, timezone
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=self._lookback_minutes)
        ).isoformat()

        half = self._max_events // 2
        info_limit = self._max_events // 3
        try:
            criticals = await self._event_repo.list_recent(
                severity="CRITICAL", since=since, limit=half,
            )
            warnings = await self._event_repo.list_recent(
                severity="WARNING", since=since, limit=half,
            )
            info_events = await self._event_repo.list_recent(
                severity="INFO", since=since, limit=info_limit,
            )
        except Exception:
            logger.exception("[ai_analyzer] 이벤트 조회 실패")
            return []

        merged = criticals + warnings + info_events
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
