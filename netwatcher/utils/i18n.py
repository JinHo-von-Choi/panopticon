"""백엔드 i18n 번역 유틸리티.

정적 로컬라이제이션 JSON 파일을 로드하여 알림 메시지 등을 번역한다.
프론트엔드와 동일한 JSON 구조를 공유한다.

작성자: 최진호
작성일: 2026-03-01
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class I18nManager:
    """번역 파일을 로드하고 키 기반 조회를 수행하는 매니저."""

    _instance: I18nManager | None = None

    def __new__(cls) -> I18nManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._locales = {}
            cls._instance._default_lang = "ko"
        return cls._instance

    def init(self, locales_dir: str | Path, default_lang: str = "ko") -> None:
        """지정된 디렉토리에서 모든 번역 파일을 로드한다."""
        self._default_lang = default_lang
        locales_path = Path(locales_dir)
        
        if not locales_path.exists():
            logger.warning("Locales directory not found: %s", locales_path)
            return

        for lang_dir in locales_path.iterdir():
            if lang_dir.is_dir():
                lang = lang_dir.name
                json_file = lang_dir / "translation.json"
                if json_file.exists():
                    try:
                        with open(json_file, "r", encoding="utf-8") as f:
                            self._locales[lang] = json.load(f)
                        logger.info("Loaded locale: %s", lang)
                    except Exception as e:
                        logger.error("Failed to load locale %s: %s", lang, e)

    def translate(self, key: str, lang: str | None = None, **kwargs: Any) -> str:
        """키를 사용하여 번역된 문자열을 반환한다.
        
        Args:
            key: 번역 키 (예: "engines.arp_spoof.name")
            lang: 대상 언어. None이면 초기화 시 설정된 기본 언어 사용.
            **kwargs: 문자열 치환용 변수 ({{var}} 형식 매칭).
            
        Returns:
            번역된 문자열. 키가 없으면 키 자체를 반환한다.
        """
        lang = lang or self._default_lang
        data = self._locales.get(lang)
        
        if not data:
            # 해당 언어가 없으면 기본 언어로 시도
            data = self._locales.get(self._default_lang, {})

        # 중첩 키 접근 (dot notation)
        val = data
        for part in key.split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                val = None
                break

        if not isinstance(val, str):
            return key

        # 변수 치환 ({{var}} -> kwargs['var'])
        def _replace(match: re.Match) -> str:
            var_name = match.group(1).strip()
            return str(kwargs.get(var_name, match.group(0)))

        return re.sub(r"\{\{(.+?)\}\}", _replace, val)


# 전역 인스턴스
i18n = I18nManager()
