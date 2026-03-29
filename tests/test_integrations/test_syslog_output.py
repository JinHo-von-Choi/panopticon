"""Syslog 출력 채널 단위 테스트."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netwatcher.detection.models import Alert, Severity
from netwatcher.integrations.syslog_output import (
    SyslogChannel,
    format_cef,
    format_rfc5424,
    _build_pri,
)


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        engine="arp_spoof",
        severity=Severity.CRITICAL,
        title="ARP Spoofing Detected",
        description="Possible ARP spoofing from 192.168.1.100",
        source_ip="192.168.1.100",
        source_mac="aa:bb:cc:dd:ee:ff",
        dest_ip="192.168.1.1",
        dest_mac="11:22:33:44:55:66",
        confidence=0.95,
        mitre_attack_id="T1557.002",
        metadata={"arp_count": 20},
    )
    defaults.update(overrides)
    return Alert(**defaults)


class TestPriority:
    def test_critical(self):
        assert _build_pri(Severity.CRITICAL) == 16 * 8 + 2

    def test_warning(self):
        assert _build_pri(Severity.WARNING) == 16 * 8 + 4

    def test_info(self):
        assert _build_pri(Severity.INFO) == 16 * 8 + 6


class TestRfc5424Format:
    def test_basic_structure(self):
        alert = _make_alert()
        msg   = format_rfc5424(alert)

        assert msg.startswith(f"<{16 * 8 + 2}>1 ")
        assert "NetWatcher" in msg
        assert "arp_spoof" in msg
        assert "[netwatcher@0" in msg
        assert 'src="192.168.1.100"' in msg
        assert 'dst="192.168.1.1"' in msg

    def test_no_source_dest(self):
        alert = _make_alert(source_ip=None, dest_ip=None)
        msg   = format_rfc5424(alert)

        assert 'src=' not in msg
        assert 'dst=' not in msg

    def test_mitre_id_in_sd(self):
        alert = _make_alert()
        msg   = format_rfc5424(alert)

        assert 'mitreAttackId="T1557.002"' in msg


class TestCefFormat:
    def test_basic_structure(self):
        alert = _make_alert()
        msg   = format_cef(alert)

        assert msg.startswith("CEF:0|Panopticon|NetWatcher|1.0|")
        assert "arp_spoof" in msg
        assert "ARP Spoofing Detected" in msg

    def test_severity_mapping(self):
        alert = _make_alert(severity=Severity.CRITICAL)
        msg   = format_cef(alert)
        # CRITICAL -> syslog 2 -> CEF 10
        parts = msg.split("|")
        assert parts[6] == "10"

    def test_extensions(self):
        alert = _make_alert()
        msg   = format_cef(alert)

        assert "src=192.168.1.100" in msg
        assert "dst=192.168.1.1" in msg
        assert "smac=aa:bb:cc:dd:ee:ff" in msg
        assert "dmac=11:22:33:44:55:66" in msg
        assert "cs1=T1557.002" in msg

    def test_pipe_escape(self):
        alert = _make_alert(title="Test|Pipe|Alert")
        msg   = format_cef(alert)

        assert "Test\\|Pipe\\|Alert" in msg

    def test_warning_severity(self):
        alert = _make_alert(severity=Severity.WARNING)
        msg   = format_cef(alert)
        parts = msg.split("|")
        assert parts[6] == "6"


class TestSyslogChannel:
    def test_channel_init(self):
        config = {
            "enabled": True,
            "host": "syslog.example.com",
            "port": 514,
            "protocol": "udp",
            "format": "cef",
            "min_severity": "WARNING",
        }
        ch = SyslogChannel(config)
        assert ch.name == "syslog"
        assert ch._host == "syslog.example.com"
        assert ch._protocol == "udp"
        assert ch._format == "cef"

    def test_should_send_filtering(self):
        config = {"enabled": True, "min_severity": "WARNING"}
        ch = SyslogChannel(config)

        alert_info = _make_alert(severity=Severity.INFO)
        alert_warn = _make_alert(severity=Severity.WARNING)
        alert_crit = _make_alert(severity=Severity.CRITICAL)

        assert not ch.should_send(alert_info)
        assert ch.should_send(alert_warn)
        assert ch.should_send(alert_crit)

    @pytest.mark.asyncio
    async def test_send_udp(self):
        config = {"enabled": True, "host": "localhost", "port": 514, "protocol": "udp", "format": "cef"}
        ch    = SyslogChannel(config)
        alert = _make_alert()

        mock_transport = MagicMock()
        mock_transport.sendto = MagicMock()
        mock_transport.close  = MagicMock()

        async def fake_endpoint(*args, **kwargs):
            return mock_transport, MagicMock()

        with patch.object(asyncio.get_running_loop(), "create_datagram_endpoint", side_effect=fake_endpoint):
            result = await ch.send(alert)

        assert result is True
        mock_transport.sendto.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_unsupported_protocol(self):
        config = {"enabled": True, "host": "localhost", "port": 514, "protocol": "ftp", "format": "cef"}
        ch    = SyslogChannel(config)
        alert = _make_alert()

        result = await ch.send(alert)
        assert result is False
