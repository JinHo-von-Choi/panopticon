"""RFC 5424 / CEF 형식 Syslog 출력 채널.

UDP, TCP, TLS 전송을 지원하며 NotificationChannel 인터페이스를 구현한다.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import time
from typing import Any

from netwatcher.alerts.channels.base import NotificationChannel
from netwatcher.detection.models import Alert, Severity

logger = logging.getLogger("netwatcher.integrations.syslog")

# Syslog facility: local0 (16)
_FACILITY = 16

# Severity -> syslog severity 매핑
_SYSLOG_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 2,  # critical
    Severity.WARNING:  4,  # warning
    Severity.INFO:     6,  # informational
}

_HOSTNAME = socket.gethostname()
_PID      = str(os.getpid())


def _build_pri(severity: Severity) -> int:
    """RFC 5424 PRI 값을 계산한다: facility * 8 + severity."""
    return _FACILITY * 8 + _SYSLOG_SEVERITY.get(severity, 6)


def format_rfc5424(alert: Alert) -> str:
    """Alert를 RFC 5424 메시지로 포맷팅한다.

    형식: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    """
    pri     = _build_pri(alert.severity)
    ts      = alert.timestamp
    app     = "NetWatcher"
    procid  = _PID
    msgid   = alert.engine
    sd      = _build_structured_data(alert)
    msg     = f"{alert.title}: {alert.description}"

    return f"<{pri}>1 {ts} {_HOSTNAME} {app} {procid} {msgid} {sd} {msg}"


def _build_structured_data(alert: Alert) -> str:
    """RFC 5424 structured data 요소를 생성한다."""
    parts: list[str] = []

    parts.append(f'severity="{alert.severity.value}"')
    parts.append(f'confidence="{alert.confidence}"')
    if alert.source_ip:
        parts.append(f'src="{alert.source_ip}"')
    if alert.dest_ip:
        parts.append(f'dst="{alert.dest_ip}"')
    if alert.mitre_attack_id:
        parts.append(f'mitreAttackId="{alert.mitre_attack_id}"')

    return f'[netwatcher@0 {" ".join(parts)}]'


def format_cef(alert: Alert) -> str:
    """Alert를 CEF(Common Event Format) 메시지로 포맷팅한다.

    형식: CEF:0|Panopticon|NetWatcher|1.0|{engine}|{title}|{severity_int}|extensions
    """
    sev_int = _SYSLOG_SEVERITY.get(alert.severity, 6)
    # CEF severity: 0-10 scale, map syslog -> CEF
    cef_sev = {2: 10, 4: 6, 6: 3}.get(sev_int, 3)

    title_escaped  = _cef_escape(alert.title)
    engine_escaped = _cef_escape(alert.engine)

    extensions: list[str] = []
    if alert.source_ip:
        extensions.append(f"src={alert.source_ip}")
    if alert.dest_ip:
        extensions.append(f"dst={alert.dest_ip}")
    if alert.source_mac:
        extensions.append(f"smac={alert.source_mac}")
    if alert.dest_mac:
        extensions.append(f"dmac={alert.dest_mac}")

    extensions.append(f"msg={_cef_escape(alert.description)}")
    extensions.append(f"cn1={alert.confidence}")
    extensions.append(f"cn1Label=confidence")
    extensions.append(f"rt={alert.timestamp}")

    if alert.mitre_attack_id:
        extensions.append(f"cs1={alert.mitre_attack_id}")
        extensions.append(f"cs1Label=mitreAttackId")

    ext_str = " ".join(extensions)
    return f"CEF:0|Panopticon|NetWatcher|1.0|{engine_escaped}|{title_escaped}|{cef_sev}|{ext_str}"


def _cef_escape(value: str) -> str:
    """CEF 헤더 필드에서 특수문자를 이스케이프한다."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


class SyslogChannel(NotificationChannel):
    """Syslog(UDP/TCP/TLS) 전송 채널."""

    name = "syslog"

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._host     = config.get("host", "localhost")
        self._port     = config.get("port", 514)
        self._protocol = config.get("protocol", "udp").lower()
        self._format   = config.get("format", "cef").lower()
        self._tls_ca   = config.get("tls_ca_cert", "")

    def _format_message_syslog(self, alert: Alert) -> str:
        """설정된 형식에 따라 syslog 메시지를 생성한다."""
        if self._format == "rfc5424":
            return format_rfc5424(alert)
        return format_cef(alert)

    async def send(self, alert: Alert) -> bool:
        """알림을 syslog 서버로 전송한다."""
        message = self._format_message_syslog(alert)
        data    = message.encode("utf-8")

        try:
            if self._protocol == "udp":
                return await self._send_udp(data)
            elif self._protocol == "tcp":
                return await self._send_tcp(data)
            elif self._protocol == "tls":
                return await self._send_tls(data)
            else:
                logger.error("지원하지 않는 syslog 프로토콜: %s", self._protocol)
                return False
        except Exception:
            logger.exception("Syslog 전송 실패 (%s:%d)", self._host, self._port)
            return False

    async def _send_udp(self, data: bytes) -> bool:
        """UDP로 syslog 메시지를 전송한다."""
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(self._host, self._port),
        )
        try:
            transport.sendto(data)
            return True
        finally:
            transport.close()

    async def _send_tcp(self, data: bytes) -> bool:
        """TCP로 syslog 메시지를 전송한다 (octet-counting framing)."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port),
            timeout=10,
        )
        try:
            framed = f"{len(data)} ".encode("utf-8") + data
            writer.write(framed)
            await writer.drain()
            return True
        finally:
            writer.close()
            await writer.wait_closed()

    async def _send_tls(self, data: bytes) -> bool:
        """TLS로 syslog 메시지를 전송한다."""
        ctx = ssl.create_default_context()
        if self._tls_ca:
            ctx.load_verify_locations(self._tls_ca)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port, ssl=ctx),
            timeout=10,
        )
        try:
            framed = f"{len(data)} ".encode("utf-8") + data
            writer.write(framed)
            await writer.drain()
            return True
        finally:
            writer.close()
            await writer.wait_closed()
