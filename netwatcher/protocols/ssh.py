"""단일 패킷 검사용 경량 SSH 배너 파서.

처음 2048 바이트만 파싱한다. SSH가 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

_MAX_PAYLOAD_BYTES = 2048


def parse_ssh_banner(payload: bytes) -> dict | None:
    """SSH 배너 문자열을 파싱한다.

    SSH 배너 형식: SSH-protoversion-softwareversion SP comments CR LF

    protocol, software, comments 키를 포함하는 dict를 반환한다.
    유효한 SSH 배너가 아니면 None을 반환한다.
    """
    try:
        if not payload:
            return None

        data = payload[:_MAX_PAYLOAD_BYTES]

        # SSH 배너는 "SSH-"로 시작해야 한다
        if not data.startswith(b"SSH-"):
            return None

        # 첫 번째 줄을 가져온다
        text = data.decode("utf-8", errors="replace")
        line_end = text.find("\r\n")
        if line_end < 0:
            line_end = text.find("\n")
            if line_end < 0:
                line = text.strip()
            else:
                line = text[:line_end].strip()
        else:
            line = text[:line_end].strip()

        if not line.startswith("SSH-"):
            return None

        # "SSH-" 접두사 제거
        rest = line[4:]

        # protoversion-softwareversion [SP comments]으로 분리
        # 첫 번째 대시가 프로토콜 버전과 소프트웨어 버전을 구분
        dash_pos = rest.find("-")
        if dash_pos < 0:
            return None

        protocol = rest[:dash_pos]
        remainder = rest[dash_pos + 1:]

        if not protocol:
            return None

        # 소프트웨어 버전과 선택적 코멘트를 공백으로 구분
        space_pos = remainder.find(" ")
        if space_pos >= 0:
            software = remainder[:space_pos]
            comments = remainder[space_pos + 1:].strip() or None
        else:
            software = remainder
            comments = None

        if not software:
            return None

        return {
            "protocol": protocol,
            "software": software,
            "comments": comments,
        }
    except (UnicodeDecodeError, ValueError):
        return None
