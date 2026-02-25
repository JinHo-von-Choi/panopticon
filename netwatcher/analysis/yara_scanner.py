"""추출된 파일 분석을 위한 YARA 규칙 스캐너.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("netwatcher.analysis.yara_scanner")

_MAX_SCAN_SIZE: int = 50 * 1024 * 1024  # 50 MB
_SCAN_TIMEOUT: int = 30  # seconds


class YaraScanner:
    """추출된 파일을 YARA 규칙으로 스캔한다.

    yara-python은 선택적 의존성이다. 설치되어 있지 않으면 스캐너가
    우아하게 기능 저하된다: ``is_available()``이 ``False``를 반환하고
    모든 스캔 메서드가 빈 결과를 반환한다.
    """

    def __init__(
        self,
        rules_dir: str = "config/yara",
        max_scan_size: int = _MAX_SCAN_SIZE,
        scan_timeout: int = _SCAN_TIMEOUT,
    ) -> None:
        """YARA 스캐너를 초기화한다. 규칙 디렉토리에서 규칙을 컴파일하고 로드한다."""
        self._rules_dir = Path(rules_dir).resolve()
        self._compiled: Any = None  # yara.Rules | None
        self._available: bool = False
        self._rules_file_count: int = 0
        self._max_scan_size = max_scan_size
        self._scan_timeout = scan_timeout
        try:
            import yara  # noqa: F401
            self._available = True
            self._load_rules()
        except ImportError:
            logger.warning("yara-python not installed — YARA scanning disabled")

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """yara-python이 설치되어 사용 가능한지 반환한다."""
        return self._available

    @property
    def rules_count(self) -> int:
        """로드된 YARA 규칙 파일 수를 반환한다.

        컴파일된 규칙이 없으면 0이다. ``yara.Rules``는 직접 카운트를
        제공하지 않으므로 내부적으로 추적한다.
        """
        return self._rules_file_count

    def reload_rules(self) -> None:
        """디스크에서 YARA 규칙을 다시 읽고 재컴파일한다.

        런타임에 규칙 파일이 추가/제거될 때 핫 리로드에 유용하다.
        """
        if not self._available:
            logger.warning("Cannot reload rules — yara-python not installed")
            return
        self._load_rules()
        logger.info("YARA rules reloaded (%d rule files)", self._rules_file_count)

    def scan_file(self, file_path: str) -> list[dict[str, Any]]:
        """디스크의 파일을 컴파일된 YARA 규칙으로 스캔한다.

        ``rule``, ``tags``, ``meta`` 키를 포함하는 매치 dict 목록을 반환한다.
        YARA를 사용할 수 없거나, 컴파일된 규칙이 없거나, 파일을 읽을 수 없으면
        빈 목록을 반환한다.
        """
        if not self._available or self._compiled is None:
            return []

        import yara

        path = Path(file_path).resolve()
        if not path.exists():
            logger.warning("File not found for YARA scan: %s", file_path)
            return []

        size = path.stat().st_size
        if size > self._max_scan_size:
            logger.warning(
                "File too large for YARA scan (%d bytes, limit %d): %s",
                size, self._max_scan_size, file_path,
            )
            return []

        try:
            matches = self._compiled.match(
                str(path), timeout=self._scan_timeout,
            )
            return self._format_matches(matches)
        except yara.Error as exc:
            logger.error("YARA scan failed for %s: %s", file_path, exc)
            return []

    def scan_bytes(self, data: bytes) -> list[dict[str, Any]]:
        """인메모리 바이트를 컴파일된 YARA 규칙으로 스캔한다.

        파일 내용이 이미 메모리에 있는 ``PcapAnalyzer`` 결과와의
        통합에 유용하다.
        """
        if not self._available or self._compiled is None:
            return []

        if len(data) > self._max_scan_size:
            logger.warning(
                "Data too large for YARA scan: %d bytes (limit %d)",
                len(data), self._max_scan_size,
            )
            return []

        import yara

        try:
            matches = self._compiled.match(
                data=data, timeout=self._scan_timeout,
            )
            return self._format_matches(matches)
        except yara.Error as exc:
            logger.error("YARA in-memory scan failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        """규칙 디렉토리의 모든 ``*.yar`` / ``*.yara`` 파일을 컴파일한다.

        원자적 교체 사용: 먼저 로컬 변수에 컴파일한 후, 불일치 상태를 방지하기 위해
        한 단계에서 인스턴스 속성에 할당한다.
        YARA ``include`` 지시어를 차단하기 위해 ``includes=False``를 전달한다.
        """
        import yara

        if not self._rules_dir.is_dir():
            logger.warning("YARA rules directory does not exist: %s", self._rules_dir)
            self._compiled = None
            self._rules_file_count = 0
            return

        rule_files: dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for f in sorted(self._rules_dir.glob(ext)):
                if f.stem not in rule_files:
                    rule_files[f.stem] = str(f)

        if not rule_files:
            logger.info("No YARA rule files found in %s", self._rules_dir)
            self._compiled = None
            self._rules_file_count = 0
            return

        try:
            new_compiled = yara.compile(filepaths=rule_files, includes=False)
            # 원자적 교체: 두 필드를 함께 업데이트
            self._compiled = new_compiled
            self._rules_file_count = len(rule_files)
            logger.info(
                "Compiled %d YARA rule file(s) from %s",
                self._rules_file_count,
                self._rules_dir,
            )
        except yara.Error as exc:
            logger.error("Failed to compile YARA rules: %s", exc)
            self._compiled = None
            self._rules_file_count = 0

    @staticmethod
    def _format_matches(matches: list[Any]) -> list[dict[str, Any]]:
        """yara 매치 객체를 일반 dict로 변환한다."""
        return [
            {
                "rule": m.rule,
                "tags": m.tags,
                "meta": m.meta,
            }
            for m in matches
        ]
