"""단일 패킷 검사용 경량 HTTP/1.x 파서.

헤더의 처음 2048 바이트만 파싱한다. HTTP가 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

_HTTP_METHODS = frozenset(
    {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH",
     b"TRACE", b"CONNECT", b"DEBUG", b"TRACK", b"PROPFIND"}
)

_MAX_HEADER_BYTES = 2048


def _parse_headers(headers_block: bytes) -> dict[bytes, str]:
    """모든 헤더를 소문자 헤더 이름을 키로 하는 dict로 파싱한다."""
    result: dict[bytes, str] = {}
    for line in headers_block.split(b"\r\n"):
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        result[key.strip().lower()] = value.strip().decode("utf-8", errors="replace")
    return result


def parse_http_request(payload: bytes) -> dict | None:
    """원시 TCP 페이로드에서 HTTP 요청을 파싱한다.

    method, path, version, host, user_agent, content_type, content_length
    키를 포함하는 dict를 반환한다. 유효한 HTTP 요청이 아니면 None을 반환한다.
    """
    try:
        if not payload:
            return None

        # 헤더 영역만 제한
        data = payload[:_MAX_HEADER_BYTES]

        # 알려진 HTTP 메서드로 시작하는지 확인
        first_space = data.find(b" ")
        if first_space < 0:
            return None

        method = data[:first_space]
        if method not in _HTTP_METHODS:
            return None

        # 요청 라인: METHOD SP path SP HTTP/x.y CRLF
        first_line_end = data.find(b"\r\n")
        if first_line_end < 0:
            return None

        request_line = data[:first_line_end]
        parts = request_line.split(b" ", 2)
        if len(parts) < 3:
            return None

        method_str  = parts[0].decode("ascii", errors="replace")
        path_str    = parts[1].decode("utf-8", errors="replace")
        version_str = parts[2].decode("ascii", errors="replace")

        if not version_str.startswith("HTTP/"):
            return None

        # 헤더를 한 번만 파싱 (단일 분할)
        headers = _parse_headers(data[first_line_end + 2:])

        return {
            "method":         method_str,
            "path":           path_str,
            "version":        version_str,
            "host":           headers.get(b"host"),
            "user_agent":     headers.get(b"user-agent"),
            "content_type":   headers.get(b"content-type"),
            "content_length": headers.get(b"content-length"),
        }
    except (UnicodeDecodeError, ValueError):
        return None


def parse_http_response(payload: bytes) -> dict | None:
    """원시 TCP 페이로드에서 HTTP 응답을 파싱한다.

    version, status_code (int), reason, server, content_type 키를 포함하는
    dict를 반환한다. 유효한 HTTP 응답이 아니면 None을 반환한다.
    """
    try:
        if not payload:
            return None

        data = payload[:_MAX_HEADER_BYTES]

        if not data.startswith(b"HTTP/"):
            return None

        first_line_end = data.find(b"\r\n")
        if first_line_end < 0:
            return None

        status_line = data[:first_line_end]
        # 상태 라인: HTTP/x.y SP status_code SP reason CRLF
        parts = status_line.split(b" ", 2)
        if len(parts) < 2:
            return None

        version_str = parts[0].decode("ascii", errors="replace")
        try:
            status_code = int(parts[1])
        except (ValueError, IndexError):
            return None

        reason_str = ""
        if len(parts) >= 3:
            reason_str = parts[2].decode("utf-8", errors="replace")

        headers = _parse_headers(data[first_line_end + 2:])

        return {
            "version":      version_str,
            "status_code":  status_code,
            "reason":       reason_str,
            "server":       headers.get(b"server"),
            "content_type": headers.get(b"content-type"),
        }
    except (UnicodeDecodeError, ValueError):
        return None
