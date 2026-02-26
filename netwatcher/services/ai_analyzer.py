"""AIAnalyzerService — GitHub Copilot CLI 기반 오탐률 자동 감소 서비스.

주기적으로 CRITICAL/WARNING 이벤트를 배치 분석하여:
- CONFIRMED_THREAT: 알림 재전송 (rate limit 우회)
- FALSE_POSITIVE:   엔진 임계값 자동 상향 + 핫리로드
- UNCERTAIN:        로그 기록만

작성자: 최진호
작성일: 2026-02-27
"""

from __future__ import annotations

import asyncio
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
    """GitHub Copilot CLI 기반 오탐률 자동 감소 서비스."""

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

        self._interval_seconds: int = int(ai_cfg.get("interval_minutes",  15)) * 60
        self._lookback_minutes: int = int(ai_cfg.get("lookback_minutes",  30))
        self._max_events:       int = int(ai_cfg.get("max_events",        50))
        self._fp_threshold:     int = int(ai_cfg.get("consecutive_fp_threshold", 2))
        self._max_pct:          int = int(ai_cfg.get("max_threshold_increase_pct", 20))
        self._timeout:          int = int(ai_cfg.get("copilot_timeout_seconds", 60))

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
