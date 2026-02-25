"""자산 변경 감지: 이전 스냅샷과 현재 기기 목록을 비교하여 변경 사항을 반환한다 (순수 함수)."""

from __future__ import annotations

import enum
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from netwatcher.inventory.risk_scorer import _DANGEROUS_PORTS, assess


class ChangeType(str, enum.Enum):
    RISK_ESCALATED = "risk_escalated"
    DANGEROUS_PORT = "dangerous_port_opened"
    IP_CHANGED     = "ip_changed"
    OFFLINE        = "device_offline"


class AssetChange(NamedTuple):
    mac:         str
    change_type: ChangeType
    title:       str
    description: str
    severity:    str   # "INFO" | "WARNING" | "CRITICAL"
    source_ip:   str | None


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------

def _device_label(device: dict) -> str:
    """기기를 대표하는 표시 이름을 반환한다 (nickname > hostname > ip > mac 우선순위)."""
    return (
        str(device.get("nickname") or "").strip()
        or str(device.get("hostname") or "").strip()
        or str(device.get("ip_address") or "").strip()
        or str(device.get("mac_address") or "unknown").strip()
    )


def _to_set(ports_val) -> set[int]:
    """open_ports 컬럼 값(list 또는 None)을 int set으로 변환한다."""
    if not ports_val:
        return set()
    return {int(p) for p in ports_val}


def _parse_last_seen(value, fallback: datetime) -> datetime:
    """last_seen 값을 timezone-aware datetime 으로 변환한다.

    asyncpg 는 datetime 객체를, 테스트 픽스처는 isoformat 문자열을 건낼 수 있다.
    파싱 실패 시 fallback 을 반환한다.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return fallback


# ---------------------------------------------------------------------------
# 공개 API
# ---------------------------------------------------------------------------

def detect_changes(
    prev: dict[str, dict],
    curr_devices: list[dict],
    offline_minutes: int = 60,
) -> tuple[list[AssetChange], dict[str, dict]]:
    """이전 스냅샷과 현재 기기 목록을 비교하여 변경 사항 및 새 스냅샷을 반환한다.

    Args:
        prev: mac → DeviceState dict.
              필드: risk_level, open_ports (set[int]), ip (str), is_known (bool),
                   label (str), last_seen (datetime), offline_alerted (bool)
        curr_devices: DeviceRepository.list_all() 결과 — 실제 DB row dict 목록
        offline_minutes: 마지막 관찰 후 오프라인으로 간주할 분 수

    Returns:
        (changes, new_snapshot) tuple.
        new_snapshot 은 다음 호출 시 prev 로 전달한다.
    """
    changes: list[AssetChange] = []
    now               = datetime.now(timezone.utc)
    offline_threshold = timedelta(minutes=offline_minutes)

    # mac_address 는 asyncpg 에서 문자열로 반환됨
    curr_by_mac: dict[str, dict] = {str(d["mac_address"]): d for d in curr_devices}
    new_snapshot: dict[str, dict] = {}

    # ── 온라인 기기 처리 ───────────────────────────────────────────────────
    for mac, device in curr_by_mac.items():
        ra       = assess(device)
        curr_ip  = str(device.get("ip_address") or "").strip()
        ports    = _to_set(device.get("open_ports"))
        label    = _device_label(device)
        last_seen = _parse_last_seen(device.get("last_seen"), now)

        new_snapshot[mac] = {
            "risk_level":      ra.level,
            "open_ports":      ports,
            "ip":              curr_ip,
            "is_known":        bool(device.get("is_known", False)),
            "label":           label,
            "last_seen":       last_seen,
            "offline_alerted": False,
        }

        if mac not in prev:
            # 처음 관찰되는 기기 — 스냅샷만 추가, 알림 없음
            continue

        p = prev[mac]

        # 1. 위험도 high 상승 감지
        if p.get("risk_level") != "high" and ra.level == "high":
            changes.append(AssetChange(
                mac         = mac,
                change_type = ChangeType.RISK_ESCALATED,
                title       = f"고위험 기기 감지: {label}",
                description = (
                    f"{label} ({mac}) 위험도가 "
                    f"{p.get('risk_level', 'unknown')} → high 로 상승했습니다. "
                    f"위험 점수: {ra.score}"
                ),
                severity    = "WARNING",
                source_ip   = curr_ip or None,
            ))

        # 2. 고위험 포트 신규 오픈 감지
        prev_ports    = _to_set(p.get("open_ports"))
        new_dangerous = (ports & _DANGEROUS_PORTS) - prev_ports
        if new_dangerous:
            port_list = ", ".join(str(pt) for pt in sorted(new_dangerous))
            changes.append(AssetChange(
                mac         = mac,
                change_type = ChangeType.DANGEROUS_PORT,
                title       = f"고위험 포트 오픈: {label}",
                description = (
                    f"{label} ({mac}) 에서 고위험 포트 {port_list}가 새로 열렸습니다."
                ),
                severity    = "WARNING",
                source_ip   = curr_ip or None,
            ))

        # 3. 등록된 기기 IP 변경 감지 (이전/현재 IP 모두 존재할 때만)
        prev_ip = p.get("ip") or ""
        if bool(device.get("is_known")) and prev_ip and curr_ip and prev_ip != curr_ip:
            changes.append(AssetChange(
                mac         = mac,
                change_type = ChangeType.IP_CHANGED,
                title       = f"등록 기기 IP 변경: {label}",
                description = (
                    f"등록된 기기 {label} ({mac}) IP가 {prev_ip} → {curr_ip} 로 변경됐습니다."
                ),
                severity    = "INFO",
                source_ip   = curr_ip or None,
            ))

    # ── 오프라인 감지: 이전 스냅샷에 있었지만 현재 없는 기기 ─────────────────
    for mac, p in prev.items():
        if mac in curr_by_mac:
            continue  # 온라인 — 위에서 이미 처리됨

        last_seen_p  = p.get("last_seen")
        if isinstance(last_seen_p, datetime):
            ts = last_seen_p if last_seen_p.tzinfo else last_seen_p.replace(tzinfo=timezone.utc)
            elapsed = now - ts
        else:
            # last_seen 정보 없음 → 임계값 충족으로 처리
            elapsed = offline_threshold

        already_alerted = bool(p.get("offline_alerted", False))
        new_snapshot[mac] = {
            **p,
            "offline_alerted": already_alerted or (elapsed >= offline_threshold),
        }

        if elapsed >= offline_threshold and not already_alerted:
            label = p.get("label") or mac
            minutes_gone = int(elapsed.total_seconds() // 60)
            changes.append(AssetChange(
                mac         = mac,
                change_type = ChangeType.OFFLINE,
                title       = f"기기 오프라인: {label}",
                description = (
                    f"{label} ({mac}) 가 {minutes_gone}분째 관찰되지 않습니다."
                ),
                severity    = "INFO",
                source_ip   = p.get("ip") or None,
            ))

    return changes, new_snapshot
