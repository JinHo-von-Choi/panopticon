"""Pydantic v2 요청/응답 스키마 검증 테스트."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netwatcher.web.schemas import (
    BlockAddRequest,
    EngineConfigUpdate,
    EventQuery,
    LoginRequest,
    PortRange,
    WhitelistAddRequest,
)


class TestLoginRequest:
    def test_valid(self):
        req = LoginRequest(username="admin", password="pass123")
        assert req.username == "admin"
        assert req.password == "pass123"

    def test_empty_username_rejected(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="", password="pass123")

    def test_empty_password_rejected(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="admin", password="")

    def test_too_long_username_rejected(self):
        with pytest.raises(ValidationError):
            LoginRequest(username="a" * 101, password="pass123")

    def test_missing_fields_rejected(self):
        with pytest.raises(ValidationError):
            LoginRequest()


class TestWhitelistAddRequest:
    def test_valid_ip(self):
        req = WhitelistAddRequest(type="ip", value="192.168.1.1")
        assert req.type == "ip"
        assert req.value == "192.168.1.1"

    def test_valid_mac(self):
        req = WhitelistAddRequest(type="mac", value="aa:bb:cc:dd:ee:ff")
        assert req.type == "mac"

    def test_valid_domain(self):
        req = WhitelistAddRequest(type="domain", value="example.com")
        assert req.type == "domain"

    def test_valid_ip_range(self):
        req = WhitelistAddRequest(type="ip_range", value="10.0.0.0/24")
        assert req.type == "ip_range"

    def test_invalid_type_rejected(self):
        with pytest.raises(ValidationError):
            WhitelistAddRequest(type="invalid", value="test")

    def test_empty_value_rejected(self):
        with pytest.raises(ValidationError):
            WhitelistAddRequest(type="ip", value="")

    def test_whitespace_only_value_rejected(self):
        with pytest.raises(ValidationError):
            WhitelistAddRequest(type="ip", value="   ")


class TestBlockAddRequest:
    def test_valid_ip(self):
        req = BlockAddRequest(value="1.2.3.4")
        assert req.value == "1.2.3.4"

    def test_valid_cidr(self):
        req = BlockAddRequest(value="10.0.0.0/8")
        assert req.value == "10.0.0.0/8"

    def test_valid_domain(self):
        req = BlockAddRequest(value="malicious.example.com")
        assert req.value == "malicious.example.com"

    def test_valid_with_notes(self):
        req = BlockAddRequest(value="1.2.3.4", notes="Known C2 server")
        assert req.notes == "Known C2 server"

    def test_invalid_value_rejected(self):
        with pytest.raises(ValidationError):
            BlockAddRequest(value="not_an_ip_or_domain")

    def test_empty_value_rejected(self):
        with pytest.raises(ValidationError):
            BlockAddRequest(value="")

    def test_whitespace_only_rejected(self):
        with pytest.raises(ValidationError):
            BlockAddRequest(value="   ")

    def test_ipv6_valid(self):
        req = BlockAddRequest(value="2001:db8::1")
        assert req.value == "2001:db8::1"


class TestEngineConfigUpdate:
    def test_valid(self):
        req = EngineConfigUpdate(config={"enabled": True, "threshold": 10})
        assert req.config["enabled"] is True

    def test_empty_config_rejected(self):
        with pytest.raises(ValidationError):
            EngineConfigUpdate(config={})


class TestEventQuery:
    def test_defaults(self):
        q = EventQuery()
        assert q.limit == 50
        assert q.offset == 0
        assert q.engine is None
        assert q.severity is None
        assert q.source_ip is None

    def test_valid_query(self):
        q = EventQuery(limit=10, offset=5, engine="arp_spoof", severity="CRITICAL", source_ip="10.0.0.1")
        assert q.limit == 10
        assert q.source_ip == "10.0.0.1"

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            EventQuery(severity="INVALID")

    def test_invalid_source_ip_rejected(self):
        with pytest.raises(ValidationError):
            EventQuery(source_ip="not_an_ip")

    def test_limit_too_large_rejected(self):
        with pytest.raises(ValidationError):
            EventQuery(limit=1001)

    def test_limit_zero_rejected(self):
        with pytest.raises(ValidationError):
            EventQuery(limit=0)

    def test_negative_offset_rejected(self):
        with pytest.raises(ValidationError):
            EventQuery(offset=-1)

    def test_valid_ipv6_source_ip(self):
        q = EventQuery(source_ip="::1")
        assert q.source_ip == "::1"


class TestPortRange:
    def test_valid_range(self):
        pr = PortRange(start=80, end=443)
        assert pr.start == 80
        assert pr.end == 443

    def test_single_port(self):
        pr = PortRange(start=8080, end=8080)
        assert pr.start == pr.end

    def test_invalid_end_less_than_start(self):
        with pytest.raises(ValidationError):
            PortRange(start=443, end=80)

    def test_port_below_1_rejected(self):
        with pytest.raises(ValidationError):
            PortRange(start=0, end=80)

    def test_port_above_65535_rejected(self):
        with pytest.raises(ValidationError):
            PortRange(start=1, end=70000)
