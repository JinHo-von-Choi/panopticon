"""Suricata .rules 형식 파서.

Suricata 호환 규칙 파일을 파싱하여 SignatureRule 인스턴스로 변환한다.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from netwatcher.detection.engines.signature_rule import SignatureRule
from netwatcher.detection.models import Severity

logger = logging.getLogger("netwatcher.detection.engines.suricata_parser")

_SEVERITY_MAP: dict[str, Severity] = {
    "trojan-activity":        Severity.CRITICAL,
    "attempted-admin":        Severity.CRITICAL,
    "successful-admin":       Severity.CRITICAL,
    "attempted-user":         Severity.CRITICAL,
    "successful-user":        Severity.CRITICAL,
    "web-application-attack": Severity.CRITICAL,
    "attempted-dos":          Severity.WARNING,
    "attempted-recon":        Severity.WARNING,
    "misc-attack":            Severity.WARNING,
    "policy-violation":       Severity.INFO,
    "not-suspicious":         Severity.INFO,
    "misc-activity":          Severity.INFO,
}

_ACTION_SEVERITY: dict[str, Severity] = {
    "alert":  Severity.WARNING,
    "drop":   Severity.CRITICAL,
    "reject": Severity.CRITICAL,
    "pass":   Severity.INFO,
    "log":    Severity.INFO,
}

_HEADER_RE = re.compile(
    r"^(?P<action>\w+)\s+"
    r"(?P<proto>\w+)\s+"
    r"(?P<src>[^\s]+)\s+"
    r"(?P<src_port>[^\s]+)\s+"
    r"(?P<direction>->|<>)\s+"
    r"(?P<dst>[^\s]+)\s+"
    r"(?P<dst_port>[^\s]+)\s+"
    r"\((?P<options>.*)\)\s*$",
    re.DOTALL,
)


def _expand_variable(token: str, variables: dict[str, str]) -> str | None:
    """변수를 치환한다. 예: $HOME_NET -> 192.168.0.0/16."""
    token = token.strip()
    if token.startswith("$"):
        return variables.get(token[1:], variables.get(token, None))
    if token == "any":
        return None
    return token


def _parse_port(token: str, variables: dict[str, str]) -> int | list[int] | None:
    """포트 표현식을 파싱한다. any, 단일 포트, [포트,포트,...] 형식을 지원한다."""
    token = token.strip()
    if token == "any":
        return None

    if token.startswith("$"):
        resolved = variables.get(token[1:], variables.get(token))
        if resolved is None:
            return None
        token = resolved

    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1]
        ports: list[int] = []
        for part in inner.split(","):
            part = part.strip()
            if not part:
                continue
            if part.startswith("!"):
                continue
            try:
                ports.append(int(part))
            except ValueError:
                pass
        return ports if len(ports) != 1 else ports[0]

    try:
        return int(token)
    except ValueError:
        return None


def _parse_hex_content(raw: str) -> str:
    """content 내 |hex hex| 패턴을 바이트로 변환한다."""
    result: list[str] = []
    i = 0
    while i < len(raw):
        if raw[i] == "|":
            end = raw.index("|", i + 1)
            hex_str = raw[i + 1:end].strip()
            for h in hex_str.split():
                result.append(chr(int(h, 16)))
            i = end + 1
        else:
            result.append(raw[i])
            i += 1
    return "".join(result)


def _parse_options(options_str: str) -> list[tuple[str, str | None]]:
    """Suricata 옵션 문자열을 (key, value) 쌍 리스트로 파싱한다.

    세미콜론 구분자를 사용하되, 따옴표와 슬래시 내부의 세미콜론은 무시한다.
    """
    parsed: list[tuple[str, str | None]] = []
    current: list[str] = []
    in_quote   = False
    in_pcre    = False
    pcre_delim = "/"
    i          = 0
    s          = options_str.strip()

    while i < len(s):
        ch = s[i]
        if in_pcre:
            current.append(ch)
            if ch == "\\" and i + 1 < len(s):
                current.append(s[i + 1])
                i += 2
                continue
            if ch == pcre_delim and len(current) > 1:
                while i + 1 < len(s) and s[i + 1].isalpha():
                    i += 1
                    current.append(s[i])
                in_pcre = False
            i += 1
            continue

        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            i += 1
            continue

        if not in_quote and ch == ";":
            token = "".join(current).strip()
            if token:
                if ":" in token:
                    key, _, val = token.partition(":")
                    parsed.append((key.strip(), val.strip()))
                else:
                    parsed.append((token, None))
            current = []
            i += 1
            continue

        if not in_quote and not in_pcre:
            joined = "".join(current).strip()
            if joined.startswith("pcre:") and ch == "/" and joined.endswith(":"):
                in_pcre    = True
                pcre_delim = "/"

        current.append(ch)
        i += 1

    token = "".join(current).strip()
    if token:
        if ":" in token:
            key, _, val = token.partition(":")
            parsed.append((key.strip(), val.strip()))
        else:
            parsed.append((token, None))

    return parsed


def _compile_pcre(pattern_str: str) -> re.Pattern[str] | None:
    """Suricata PCRE 패턴을 Python re.Pattern으로 컴파일한다.

    형식: "/pattern/flags" 또는 "pattern"
    지원 플래그: i(IGNORECASE), s(DOTALL), m(MULTILINE)
    """
    pattern_str = pattern_str.strip()
    if pattern_str.startswith('"') and pattern_str.endswith('"'):
        pattern_str = pattern_str[1:-1]

    if pattern_str.startswith("/"):
        last_slash = pattern_str.rfind("/")
        if last_slash > 0:
            raw_pattern = pattern_str[1:last_slash]
            flags_str   = pattern_str[last_slash + 1:]
            flags       = 0
            if "i" in flags_str:
                flags |= re.IGNORECASE
            if "s" in flags_str:
                flags |= re.DOTALL
            if "m" in flags_str:
                flags |= re.MULTILINE
            try:
                return re.compile(raw_pattern, flags)
            except re.error:
                logger.warning("Invalid PCRE pattern: %s", pattern_str)
                return None

    try:
        return re.compile(pattern_str)
    except re.error:
        logger.warning("Invalid PCRE pattern: %s", pattern_str)
        return None


def parse_rule(line: str, variables: dict[str, str] | None = None) -> SignatureRule | None:
    """한 줄의 Suricata 규칙을 파싱하여 SignatureRule을 반환한다.

    파싱 실패 시 None을 반환한다.
    """
    variables = variables or {}
    line      = line.strip()

    if not line or line.startswith("#"):
        return None

    m = _HEADER_RE.match(line)
    if not m:
        logger.debug("Rule header parse failed: %.80s...", line)
        return None

    action     = m.group("action").lower()
    proto      = m.group("proto").lower()
    src_token  = m.group("src")
    src_port_t = m.group("src_port")
    dst_token  = m.group("dst")
    dst_port_t = m.group("dst_port")
    options_s  = m.group("options")

    src_ip   = _expand_variable(src_token, variables)
    dst_ip   = _expand_variable(dst_token, variables)
    src_port = _parse_port(src_port_t, variables)
    dst_port = _parse_port(dst_port_t, variables)

    options = _parse_options(options_s)

    msg:        str               = ""
    sid:        str               = ""
    rev:        str               = "1"
    classtype:  str               = ""
    content_list: list[str]       = []
    pcre_list:    list[re.Pattern] = []
    nocase_flag = False
    flow_str:   str | None        = None
    flowbits:   dict[str, str] | None = None
    references: list[str]         = []
    rule_metadata: dict[str, Any] = {}

    for key, val in options:
        if key == "msg" and val:
            msg = val.strip('"')
        elif key == "content" and val:
            raw = val.strip('"')
            if "|" in raw:
                content_list.append(_parse_hex_content(raw))
            else:
                content_list.append(raw)
        elif key == "nocase":
            nocase_flag = True
        elif key == "pcre" and val:
            compiled = _compile_pcre(val)
            if compiled:
                pcre_list.append(compiled)
        elif key == "flow" and val:
            flow_str = val.strip('"')
        elif key == "flowbits" and val:
            parts    = val.strip('"').split(",", 1)
            fb_action = parts[0].strip()
            fb_name   = parts[1].strip() if len(parts) > 1 else ""
            flowbits  = {"action": fb_action, "name": fb_name}
        elif key == "sid" and val:
            sid = val.strip()
        elif key == "rev" and val:
            rev = val.strip()
        elif key == "classtype" and val:
            classtype = val.strip('"').strip()
        elif key == "reference" and val:
            references.append(val.strip('"'))
        elif key in ("depth", "offset", "distance", "within"):
            pass
        elif key == "metadata" and val:
            rule_metadata["raw"] = val.strip('"')

    severity = _SEVERITY_MAP.get(classtype, _ACTION_SEVERITY.get(action, Severity.WARNING))

    rule_id = f"SID-{sid}" if sid else f"SURI-{hash(line) & 0xFFFFFFFF:08X}"

    meta: dict[str, Any] = {
        "sid":       sid,
        "rev":       rev,
        "classtype": classtype,
        "msg":       msg,
    }
    if references:
        meta["references"] = references
    if rule_metadata:
        meta.update(rule_metadata)

    return SignatureRule(
        id=rule_id,
        name=msg or f"Suricata Rule {sid}",
        severity=severity,
        protocol=proto if proto != "ip" else None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        content=content_list,
        content_nocase=nocase_flag,
        nocase=nocase_flag,
        pcre=pcre_list,
        flow=flow_str,
        flowbits=flowbits,
        metadata=meta,
        enabled=True,
    )


def load_rules_file(
    path: Path,
    variables: dict[str, str] | None = None,
) -> list[SignatureRule]:
    """Suricata .rules 파일에서 규칙을 로드한다."""
    variables = variables or {}
    rules: list[SignatureRule] = []

    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        logger.exception("Failed to read rules file: %s", path)
        return rules

    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rule = parse_rule(line, variables)
            if rule is not None:
                rules.append(rule)
        except Exception:
            logger.exception("Failed to parse rule at %s:%d", path, line_no)

    logger.info("Loaded %d Suricata rules from %s", len(rules), path)
    return rules
