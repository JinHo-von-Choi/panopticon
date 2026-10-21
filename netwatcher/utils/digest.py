"""64자리 16진수 지문 검증.

버전 지문·해시·서명 지문은 모두 같은 형식이다. 형식을 한 곳에서 정의한다 —
열한 곳의 정규식이 조금씩 달라지면 어느 경로가 약해지는지 알 수 없다.
"""

from __future__ import annotations

import re

# 본문 어디에나 놓이는 64자리 소문자 16진수.
SHA256_HEX_PATTERN = re.compile(r"[a-f0-9]{64}")

# 문자열 전체가 64자리 16진수여야 하는 경우(요청 필드).
BASE_VERSION_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def is_sha256_hex(value: object) -> bool:
    """소문자 16진수 64자리 지문인지 확인한다."""
    return isinstance(value, str) and SHA256_HEX_PATTERN.fullmatch(value) is not None
