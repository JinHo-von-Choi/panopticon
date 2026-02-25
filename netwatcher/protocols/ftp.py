"""단일 패킷 검사용 경량 FTP 파서.

처음 2048 바이트만 파싱한다. FTP가 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

_MAX_PAYLOAD_BYTES = 2048

# 이 파서가 인식하는 FTP 명령 (대소문자 무시 매칭)
_FTP_COMMANDS = frozenset({
    "USER", "PASS", "PORT", "PASV", "RETR", "STOR",
    "LIST", "CWD", "PWD", "QUIT", "TYPE", "DELE",
    "MKD", "RMD", "SYST",
})


def parse_ftp_command(payload: bytes) -> dict | None:
    """FTP 클라이언트 명령을 파싱한다.

    command, argument 키를 포함하는 dict를 반환한다.
    유효한 FTP 명령이 아니면 None을 반환한다.
    """
    try:
        if not payload:
            return None

        data = payload[:_MAX_PAYLOAD_BYTES]
        text = data.decode("utf-8", errors="replace")

        # 첫 번째 줄만 가져온다
        line_end = text.find("\r\n")
        if line_end < 0:
            line_end = text.find("\n")
            if line_end < 0:
                line = text.strip()
            else:
                line = text[:line_end].strip()
        else:
            line = text[:line_end].strip()

        if not line:
            return None

        parts = line.split(None, 1)
        if not parts:
            return None

        cmd_upper = parts[0].upper()
        if cmd_upper not in _FTP_COMMANDS:
            return None

        argument = parts[1].strip() if len(parts) > 1 else ""
        return {"command": cmd_upper, "argument": argument}
    except (UnicodeDecodeError, ValueError):
        return None


def parse_ftp_response(payload: bytes) -> dict | None:
    """FTP 서버 응답을 파싱한다.

    code (int), message 키를 포함하는 dict를 반환한다.
    유효한 FTP 응답이 아니면 None을 반환한다.
    """
    try:
        if not payload:
            return None

        data = payload[:_MAX_PAYLOAD_BYTES]
        text = data.decode("utf-8", errors="replace")

        # 첫 번째 줄을 가져온다
        line_end = text.find("\r\n")
        if line_end < 0:
            line_end = text.find("\n")
            if line_end < 0:
                line = text.strip()
            else:
                line = text[:line_end].strip()
        else:
            line = text[:line_end].strip()

        if len(line) < 3:
            return None

        # FTP 응답 형식: 3자리 코드 뒤에 공백 또는 하이픈, 그리고 메시지
        code_str = line[:3]
        if not code_str.isdigit():
            return None

        code = int(code_str)

        # 구분자는 공백 또는 하이픈이어야 함 (여러 줄 연속)
        if len(line) > 3:
            sep = line[3]
            if sep not in (" ", "-"):
                return None
            message = line[4:].strip()
        else:
            message = ""

        return {"code": code, "message": message}
    except (UnicodeDecodeError, ValueError):
        return None
