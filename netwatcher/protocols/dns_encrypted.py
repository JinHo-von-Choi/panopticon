"""단일 패킷 검사용 경량 암호화 DNS(DoT/DoH) 탐지기.

처음 2048 바이트만 파싱한다. 해당 프로토콜이 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

_MAX_PAYLOAD_BYTES = 2048

# TLS ContentType: Handshake
_TLS_HANDSHAKE = 0x16

# TLS 버전 바이트 (major, minor)
_TLS_VERSIONS = frozenset({
    (0x03, 0x01),  # TLS 1.0
    (0x03, 0x02),  # TLS 1.1
    (0x03, 0x03),  # TLS 1.2 / 1.3 ClientHello
})

# 알려진 DoH 제공자 호스트명
_KNOWN_DOH_PROVIDERS = frozenset({
    b"cloudflare-dns.com",
    b"dns.google",
    b"dns.quad9.net",
    b"doh.opendns.com",
    b"dns.adguard.com",
    b"doh.cleanbrowsing.org",
    b"dns.nextdns.io",
})

_DOH_PATH         = b"/dns-query"
_DOH_CONTENT_TYPE = b"application/dns-message"


def detect_dot(payload: bytes, dst_port: int) -> dict | None:
    """DNS-over-TLS(포트 853) 트래픽을 탐지한다.

    TLS ClientHello 시그니처와 포트 853 조합으로 판별한다.
    {"type": "dot", "tls_detected": bool} 또는 None을 반환한다.
    """
    if dst_port != 853:
        return None

    if not payload or len(payload) < 3:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # TLS Handshake 레코드 확인: ContentType(1) + Version(2)
    content_type = data[0]
    if content_type != _TLS_HANDSHAKE:
        # 포트 853이지만 TLS가 아닌 경우
        return {"type": "dot", "tls_detected": False}

    if len(data) < 3:
        return {"type": "dot", "tls_detected": False}

    version_pair = (data[1], data[2])
    tls_detected = version_pair in _TLS_VERSIONS

    return {"type": "dot", "tls_detected": tls_detected}


def detect_doh(payload: bytes, dst_port: int) -> dict | None:
    """DNS-over-HTTPS 패턴을 탐지한다.

    HTTP/1.x 요청에서 /dns-query 경로 또는 application/dns-message
    Content-Type을 확인한다. 알려진 DoH 제공자 호스트도 검사한다.
    {"type": "doh", "path": str, "method": str, "provider": str | None}
    또는 None을 반환한다.
    """
    if not payload:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]
    data_lower = data.lower()

    # /dns-query 경로가 포함된 HTTP 요청 확인
    if _DOH_PATH not in data_lower:
        # application/dns-message Content-Type도 확인
        if _DOH_CONTENT_TYPE not in data_lower:
            return None

    # HTTP 메서드 추출
    method: str | None = None
    if data.startswith(b"GET "):
        method = "GET"
    elif data.startswith(b"POST "):
        method = "POST"
    else:
        # HTTP 메서드가 아니면 탐지 불가
        return None

    # 경로 추출
    first_line_end = data.find(b"\r\n")
    if first_line_end < 0:
        first_line_end = data.find(b"\n")
    if first_line_end < 0:
        first_line_end = len(data)

    request_line = data[:first_line_end]
    parts = request_line.split(b" ", 2)
    path = parts[1].decode("utf-8", errors="replace") if len(parts) >= 2 else ""

    # 알려진 DoH 제공자 확인
    provider: str | None = None
    for host in _KNOWN_DOH_PROVIDERS:
        if host in data_lower:
            provider = host.decode("ascii")
            break

    return {
        "type":     "doh",
        "path":     path,
        "method":   method,
        "provider": provider,
    }


def detect_encrypted_dns(payload: bytes, dst_port: int) -> dict | None:
    """DoT와 DoH를 순차적으로 탐지한다.

    DoT를 먼저 시도하고, 해당하지 않으면 DoH를 시도한다.
    탐지된 결과 dict 또는 None을 반환한다.
    """
    result = detect_dot(payload, dst_port)
    if result is not None:
        return result

    return detect_doh(payload, dst_port)
