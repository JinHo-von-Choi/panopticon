"""YAML 기반 시그니처 규칙 데이터 모델."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from netwatcher.detection.models import Severity


@dataclass
class SignatureRule:
    """단일 시그니처 규칙을 표현한다."""

    id: str
    name: str
    severity: Severity = Severity.INFO
    protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | list[int] | None = None
    dst_port: int | list[int] | None = None
    flags: str | None = None
    content: list[str] = field(default_factory=list)
    content_nocase: bool = False
    regex: re.Pattern[str] | None = None
    threshold: dict[str, Any] | None = None
    enabled: bool = True
    pcre: list[re.Pattern[str]] = field(default_factory=list)
    flow: str | None = None
    flowbits: dict[str, str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    nocase: bool = False

    def __post_init__(self) -> None:
        """nocase와 content_nocase를 동기화한다."""
        if self.nocase and not self.content_nocase:
            self.content_nocase = True
        elif self.content_nocase and not self.nocase:
            self.nocase = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignatureRule:
        """YAML 딕셔너리로부터 SignatureRule 인스턴스를 생성한다."""
        severity_str = data.get("severity", "INFO").upper()
        severity = Severity(severity_str)

        regex_pattern = data.get("regex")
        compiled_regex = re.compile(regex_pattern) if regex_pattern else None

        pcre_patterns: list[re.Pattern[str]] = []
        for p in data.get("pcre", []):
            if isinstance(p, str):
                pcre_patterns.append(re.compile(p))

        nocase_val     = data.get("nocase", False)
        content_nocase = data.get("content_nocase", False)
        effective_nocase = nocase_val or content_nocase

        return cls(
            id=data["id"],
            name=data["name"],
            severity=severity,
            protocol=data.get("protocol"),
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            flags=data.get("flags"),
            content=data.get("content", []),
            content_nocase=effective_nocase,
            regex=compiled_regex,
            threshold=data.get("threshold"),
            enabled=data.get("enabled", True),
            pcre=pcre_patterns,
            flow=data.get("flow"),
            flowbits=data.get("flowbits"),
            metadata=data.get("metadata", {}),
            nocase=effective_nocase,
        )

    def matches_payload(self, payload: bytes) -> bool:
        """content 패턴과 pcre를 페이로드에 대해 검사한다.

        모든 content 항목과 pcre가 일치해야 True를 반환한다(AND 조건).
        """
        if not self.content and not self.pcre and self.regex is None:
            return True

        text: str | None = None

        if self.content:
            if text is None:
                try:
                    text = payload.decode("utf-8", errors="replace")
                except Exception:
                    text = payload.decode("latin-1")

            check_text = text.lower() if self.content_nocase else text
            for pattern in self.content:
                check_pattern = pattern.lower() if self.content_nocase else pattern
                if check_pattern not in check_text:
                    return False

        if self.regex is not None:
            if text is None:
                try:
                    text = payload.decode("utf-8", errors="replace")
                except Exception:
                    text = payload.decode("latin-1")
            if not self.regex.search(text):
                return False

        for pcre_pat in self.pcre:
            if text is None:
                try:
                    text = payload.decode("utf-8", errors="replace")
                except Exception:
                    text = payload.decode("latin-1")
            if not pcre_pat.search(text):
                return False

        return True
