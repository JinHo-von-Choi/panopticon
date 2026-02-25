"""Tests for detect_changes: pure-function asset change detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netwatcher.inventory.change_detector import (
    AssetChange,
    ChangeType,
    detect_changes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(hours_ago: float = 48.0) -> str:
    """UTC ISO 문자열 반환 (기본 48h 전 — 신규 기기 아님)."""
    return (_now() - timedelta(hours=hours_ago)).isoformat()


def _device(
    mac:         str   = "aa:bb:cc:dd:ee:01",
    ip:          str   = "192.168.1.10",
    hostname:    str   = "workstation",
    is_known:    bool  = True,
    device_type: str   = "pc",
    open_ports:  list  = None,
    first_seen:  str   = None,
    last_seen          = None,
) -> dict:
    """기본값이 설정된 '완전히 안전한' 기기 dict를 생성한다."""
    return {
        "mac_address":  mac,
        "ip_address":   ip,
        "hostname":     hostname,
        "nickname":     None,
        "is_known":     is_known,
        "device_type":  device_type,
        "open_ports":   open_ports or [],
        "first_seen":   first_seen or _ts(hours_ago=72),
        "last_seen":    last_seen or _now(),
    }


def _snap(
    mac:              str      = "aa:bb:cc:dd:ee:01",
    risk_level:       str      = "low",
    open_ports:       set      = None,
    ip:               str      = "192.168.1.10",
    is_known:         bool     = True,
    label:            str      = "workstation",
    last_seen:        datetime = None,
    offline_alerted:  bool     = False,
) -> dict:
    """스냅샷 항목 dict를 생성한다."""
    return {
        "risk_level":      risk_level,
        "open_ports":      open_ports or set(),
        "ip":              ip,
        "is_known":        is_known,
        "label":           label,
        "last_seen":       last_seen or _now(),
        "offline_alerted": offline_alerted,
    }


def _high_risk_device(**kw) -> dict:
    """risk_level=high 를 만드는 기기 dict를 반환한다.

    점수: is_known=False(+20) + unknown_type(+10) + no_hostname(+8)
          + new_device(+10) + port 23(+15) = 63 → high
    """
    return _device(
        is_known    = False,
        device_type = "unknown",
        hostname    = "",
        open_ports  = [23],
        first_seen  = _ts(hours_ago=1),
        **kw,
    )


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

class TestReturnType:
    def test_returns_tuple(self):
        changes, snap = detect_changes({}, [])
        assert isinstance(changes, list)
        assert isinstance(snap, dict)

    def test_changes_are_asset_change(self):
        dev = _high_risk_device()
        prev = {"aa:bb:cc:dd:ee:01": _snap(risk_level="low")}
        changes, _ = detect_changes(prev, [dev])
        assert all(isinstance(c, AssetChange) for c in changes)


# ---------------------------------------------------------------------------
# 빈 입력
# ---------------------------------------------------------------------------

class TestEmpty:
    def test_empty_prev_and_curr(self):
        changes, snap = detect_changes({}, [])
        assert changes == []
        assert snap   == {}

    def test_empty_prev_populates_snapshot(self):
        dev = _device()
        _, snap = detect_changes({}, [dev])
        assert "aa:bb:cc:dd:ee:01" in snap

    def test_empty_prev_no_changes_emitted(self):
        """prev 가 비어 있으면 현재 기기가 위험해도 변경 알림을 발송하지 않는다."""
        dev = _high_risk_device()
        changes, _ = detect_changes({}, [dev])
        assert changes == []


# ---------------------------------------------------------------------------
# 스냅샷 구축
# ---------------------------------------------------------------------------

class TestSnapshotBuilding:
    def test_snapshot_contains_correct_risk_level(self):
        dev = _device()   # 안전한 기기 → low
        _, snap = detect_changes({}, [dev])
        assert snap["aa:bb:cc:dd:ee:01"]["risk_level"] == "low"

    def test_snapshot_contains_ports(self):
        dev = _device(open_ports=[80, 443])
        _, snap = detect_changes({}, [dev])
        assert snap["aa:bb:cc:dd:ee:01"]["open_ports"] == {80, 443}

    def test_snapshot_contains_ip(self):
        dev = _device(ip="10.0.0.5")
        _, snap = detect_changes({}, [dev])
        assert snap["aa:bb:cc:dd:ee:01"]["ip"] == "10.0.0.5"

    def test_snapshot_offline_alerted_false_for_online(self):
        dev = _device()
        _, snap = detect_changes({}, [dev])
        assert snap["aa:bb:cc:dd:ee:01"]["offline_alerted"] is False


# ---------------------------------------------------------------------------
# RISK_ESCALATED
# ---------------------------------------------------------------------------

class TestRiskEscalated:
    def test_low_to_high_emits_change(self):
        dev  = _high_risk_device()
        prev = {"aa:bb:cc:dd:ee:01": _snap(risk_level="low")}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.RISK_ESCALATED in types

    def test_medium_to_high_emits_change(self):
        dev  = _high_risk_device()
        prev = {"aa:bb:cc:dd:ee:01": _snap(risk_level="medium")}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.RISK_ESCALATED in types

    def test_high_stays_high_no_change(self):
        """이미 high 였으면 재알림하지 않는다."""
        dev  = _high_risk_device()
        prev = {"aa:bb:cc:dd:ee:01": _snap(risk_level="high")}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.RISK_ESCALATED not in types

    def test_escalated_severity_is_warning(self):
        dev  = _high_risk_device()
        prev = {"aa:bb:cc:dd:ee:01": _snap(risk_level="low")}
        changes, _ = detect_changes(prev, [dev])
        esc = next(c for c in changes if c.change_type == ChangeType.RISK_ESCALATED)
        assert esc.severity == "WARNING"

    def test_escalated_mac_matches(self):
        dev  = _high_risk_device()
        prev = {"aa:bb:cc:dd:ee:01": _snap(risk_level="low")}
        changes, _ = detect_changes(prev, [dev])
        esc = next(c for c in changes if c.change_type == ChangeType.RISK_ESCALATED)
        assert esc.mac == "aa:bb:cc:dd:ee:01"


# ---------------------------------------------------------------------------
# DANGEROUS_PORT
# ---------------------------------------------------------------------------

class TestDangerousPort:
    def test_new_dangerous_port_emits_change(self):
        dev  = _device(open_ports=[23])
        prev = {"aa:bb:cc:dd:ee:01": _snap(open_ports=set())}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.DANGEROUS_PORT in types

    def test_already_open_dangerous_port_no_change(self):
        dev  = _device(open_ports=[23])
        prev = {"aa:bb:cc:dd:ee:01": _snap(open_ports={23})}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.DANGEROUS_PORT not in types

    def test_non_dangerous_new_port_no_change(self):
        dev  = _device(open_ports=[8080])
        prev = {"aa:bb:cc:dd:ee:01": _snap(open_ports=set())}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.DANGEROUS_PORT not in types

    def test_multiple_new_dangerous_ports_single_change(self):
        """여러 고위험 포트가 동시에 오픈돼도 단일 DANGEROUS_PORT 변경만 생성한다."""
        dev  = _device(open_ports=[21, 23])
        prev = {"aa:bb:cc:dd:ee:01": _snap(open_ports=set())}
        changes, _ = detect_changes(prev, [dev])
        dp_changes = [c for c in changes if c.change_type == ChangeType.DANGEROUS_PORT]
        assert len(dp_changes) == 1

    def test_dangerous_port_severity_is_warning(self):
        dev  = _device(open_ports=[3389])
        prev = {"aa:bb:cc:dd:ee:01": _snap(open_ports=set())}
        changes, _ = detect_changes(prev, [dev])
        dp = next(c for c in changes if c.change_type == ChangeType.DANGEROUS_PORT)
        assert dp.severity == "WARNING"

    def test_dangerous_port_description_includes_port(self):
        dev  = _device(open_ports=[23])
        prev = {"aa:bb:cc:dd:ee:01": _snap(open_ports=set())}
        changes, _ = detect_changes(prev, [dev])
        dp = next(c for c in changes if c.change_type == ChangeType.DANGEROUS_PORT)
        assert "23" in dp.description


# ---------------------------------------------------------------------------
# IP_CHANGED
# ---------------------------------------------------------------------------

class TestIpChanged:
    def test_known_device_ip_change_emits_change(self):
        dev  = _device(ip="192.168.1.20", is_known=True)
        prev = {"aa:bb:cc:dd:ee:01": _snap(ip="192.168.1.10", is_known=True)}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.IP_CHANGED in types

    def test_unknown_device_ip_change_no_alert(self):
        dev  = _device(ip="192.168.1.20", is_known=False)
        prev = {"aa:bb:cc:dd:ee:01": _snap(ip="192.168.1.10", is_known=False)}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.IP_CHANGED not in types

    def test_same_ip_no_change(self):
        dev  = _device(ip="192.168.1.10", is_known=True)
        prev = {"aa:bb:cc:dd:ee:01": _snap(ip="192.168.1.10", is_known=True)}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.IP_CHANGED not in types

    def test_no_prev_ip_no_change(self):
        """이전 IP 정보가 없으면 IP 변경 알림을 발송하지 않는다."""
        dev  = _device(ip="192.168.1.10", is_known=True)
        prev = {"aa:bb:cc:dd:ee:01": _snap(ip="", is_known=True)}
        changes, _ = detect_changes(prev, [dev])
        types = [c.change_type for c in changes]
        assert ChangeType.IP_CHANGED not in types

    def test_ip_changed_severity_is_info(self):
        dev  = _device(ip="192.168.1.20", is_known=True)
        prev = {"aa:bb:cc:dd:ee:01": _snap(ip="192.168.1.10", is_known=True)}
        changes, _ = detect_changes(prev, [dev])
        ip_ch = next(c for c in changes if c.change_type == ChangeType.IP_CHANGED)
        assert ip_ch.severity == "INFO"

    def test_ip_changed_description_contains_both_ips(self):
        dev  = _device(ip="192.168.1.20", is_known=True)
        prev = {"aa:bb:cc:dd:ee:01": _snap(ip="192.168.1.10", is_known=True)}
        changes, _ = detect_changes(prev, [dev])
        ip_ch = next(c for c in changes if c.change_type == ChangeType.IP_CHANGED)
        assert "192.168.1.10" in ip_ch.description
        assert "192.168.1.20" in ip_ch.description


# ---------------------------------------------------------------------------
# OFFLINE
# ---------------------------------------------------------------------------

class TestOffline:
    def test_offline_past_threshold_emits_change(self):
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=90),
                offline_alerted = False,
            ),
        }
        changes, _ = detect_changes(prev, [], offline_minutes=60)
        types = [c.change_type for c in changes]
        assert ChangeType.OFFLINE in types

    def test_offline_before_threshold_no_change(self):
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=30),
                offline_alerted = False,
            ),
        }
        changes, _ = detect_changes(prev, [], offline_minutes=60)
        types = [c.change_type for c in changes]
        assert ChangeType.OFFLINE not in types

    def test_already_alerted_no_duplicate(self):
        """offline_alerted=True 이면 중복 알림을 발송하지 않는다."""
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=120),
                offline_alerted = True,
            ),
        }
        changes, _ = detect_changes(prev, [], offline_minutes=60)
        types = [c.change_type for c in changes]
        assert ChangeType.OFFLINE not in types

    def test_offline_alerted_set_true_in_snapshot(self):
        """임계값 초과 시 new_snapshot의 offline_alerted 가 True 로 설정된다."""
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=90),
                offline_alerted = False,
            ),
        }
        _, snap = detect_changes(prev, [], offline_minutes=60)
        assert snap["aa:bb:cc:dd:ee:01"]["offline_alerted"] is True

    def test_offline_alerted_remains_true_when_still_offline(self):
        """이미 alerted=True 인 상태에서 계속 오프라인이면 True 를 유지한다."""
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=120),
                offline_alerted = True,
            ),
        }
        _, snap = detect_changes(prev, [], offline_minutes=60)
        assert snap["aa:bb:cc:dd:ee:01"]["offline_alerted"] is True

    def test_offline_alerted_reset_when_online(self):
        """기기가 다시 온라인이 되면 offline_alerted 가 False 로 초기화된다."""
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=120),
                offline_alerted = True,
            ),
        }
        dev = _device()
        _, snap = detect_changes(prev, [dev], offline_minutes=60)
        assert snap["aa:bb:cc:dd:ee:01"]["offline_alerted"] is False

    def test_offline_severity_is_info(self):
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=90),
                offline_alerted = False,
            ),
        }
        changes, _ = detect_changes(prev, [], offline_minutes=60)
        off = next(c for c in changes if c.change_type == ChangeType.OFFLINE)
        assert off.severity == "INFO"

    def test_offline_description_mentions_minutes(self):
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                last_seen       = _now() - timedelta(minutes=90),
                offline_alerted = False,
            ),
        }
        changes, _ = detect_changes(prev, [], offline_minutes=60)
        off = next(c for c in changes if c.change_type == ChangeType.OFFLINE)
        assert "분" in off.description


# ---------------------------------------------------------------------------
# 복합 시나리오
# ---------------------------------------------------------------------------

class TestCombined:
    def test_multiple_changes_from_single_device(self):
        """한 기기에서 위험도 상승 + 고위험 포트 오픈이 동시에 발생할 수 있다."""
        dev = _device(
            open_ports  = [23],
            is_known    = False,
            device_type = "unknown",
            hostname    = "",
            first_seen  = _ts(hours_ago=1),
        )
        prev = {
            "aa:bb:cc:dd:ee:01": _snap(
                risk_level = "low",
                open_ports = set(),
            ),
        }
        changes, _ = detect_changes(prev, [dev])
        types = {c.change_type for c in changes}
        assert ChangeType.RISK_ESCALATED in types
        assert ChangeType.DANGEROUS_PORT in types

    def test_offline_and_online_changes_in_same_call(self):
        """한 번 호출에서 다른 기기가 오프라인되고 온라인 기기에서 변경이 발생할 수 있다."""
        offline_mac = "ff:ee:dd:cc:bb:01"
        online_mac  = "aa:bb:cc:dd:ee:01"

        prev = {
            offline_mac: _snap(
                mac             = offline_mac,
                last_seen       = _now() - timedelta(minutes=90),
                offline_alerted = False,
            ),
            online_mac: _snap(
                mac        = online_mac,
                open_ports = set(),
            ),
        }
        online_dev = _device(mac=online_mac, open_ports=[23])
        changes, _ = detect_changes(prev, [online_dev], offline_minutes=60)

        types = {c.change_type for c in changes}
        assert ChangeType.OFFLINE        in types
        assert ChangeType.DANGEROUS_PORT in types

    def test_new_snapshot_includes_all_macs(self):
        """offline 기기도 new_snapshot 에 남는다."""
        offline_mac = "ff:ee:dd:cc:bb:01"
        online_mac  = "aa:bb:cc:dd:ee:01"

        prev = {
            offline_mac: _snap(
                last_seen       = _now() - timedelta(minutes=90),
                offline_alerted = False,
            ),
        }
        dev = _device(mac=online_mac)
        _, snap = detect_changes(prev, [dev], offline_minutes=60)
        assert offline_mac in snap
        assert online_mac  in snap
