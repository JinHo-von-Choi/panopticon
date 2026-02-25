"""네트워크 기기 타입 추론.

vendor(OUI), os_hint, hostname을 조합하여 기기 카테고리를 결정한다.
외부 의존성 없이 순수 규칙 기반으로 동작한다.

타입 목록: pc | mobile | printer | router | nas | server | iot | unknown
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 분류 규칙 테이블
# ---------------------------------------------------------------------------

# (소문자 키워드, 반환 타입) 순서가 우선순위
_VENDOR_RULES: list[tuple[str, str]] = [
    # 프린터
    ("xerox",       "printer"),
    ("lexmark",     "printer"),
    ("kyocera",     "printer"),
    ("konica",      "printer"),
    ("ricoh",       "printer"),
    ("brother",     "printer"),
    ("epson",       "printer"),
    ("zebra",       "printer"),
    # 라우터 / AP / 스위치
    ("cisco",       "router"),
    ("juniper",     "router"),
    ("ubiquiti",    "router"),
    ("mikrotik",    "router"),
    ("aruba",       "router"),
    ("ruckus",      "router"),
    ("zyxel",       "router"),
    ("openwrt",     "router"),
    # NAS / 스토리지
    ("synology",    "nas"),
    ("qnap",        "nas"),
    # IoT 전용 칩셋 / 플랫폼
    ("espressif",   "iot"),
    ("tuya",        "iot"),
    ("shelly",      "iot"),
    ("hikvision",   "iot"),
    ("dahua",       "iot"),
    ("axis comm",   "iot"),
    ("raspberry",   "iot"),
    # 모바일 전용 제조사
    ("oneplus",     "mobile"),
    ("xiaomi",      "mobile"),
    ("vivo",        "mobile"),
    ("oppo",        "mobile"),
    ("realme",      "mobile"),
    ("nokia",       "mobile"),
    ("motorola",    "mobile"),
]

# OS 힌트 → 타입 (완전 일치 / 접두사 포함)
_OS_RULES: list[tuple[str, str]] = [
    ("ios",       "mobile"),
    ("android",   "mobile"),
    ("ipados",    "mobile"),
    ("windows",   "pc"),
    ("macos",     "pc"),
    ("linux",     "server"),   # 포트 없으면 pc로 재분류하지 않음(server 유지)
]

# 호스트명 패턴 → 타입
_HOSTNAME_RULES: list[tuple[str, str]] = [
    # 모바일
    ("iphone",     "mobile"),
    ("ipad",       "mobile"),
    ("android",    "mobile"),
    ("galaxy",     "mobile"),
    ("pixel",      "mobile"),
    # 프린터
    ("printer",    "printer"),
    ("mfp",        "printer"),
    ("laserjet",   "printer"),
    ("officejet",  "printer"),
    ("colorjet",   "printer"),
    # 라우터 / AP
    ("router",     "router"),
    ("gateway",    "router"),
    ("switch",     "router"),
    ("-ap-",       "router"),
    # NAS
    ("nas",        "nas"),
    ("diskstation","nas"),
    ("readynas",   "nas"),
    # IoT
    ("raspi",      "iot"),
    ("esp8266",    "iot"),
    ("esp32",      "iot"),
    ("camera",     "iot"),
    ("cam-",       "iot"),
    ("hue",        "iot"),
    ("ring",       "iot"),
    ("thermostat", "iot"),
    ("smartplug",  "iot"),
    # PC
    ("desktop",    "pc"),
    ("laptop",     "pc"),
    ("workstation","pc"),
    ("macbook",    "pc"),
    ("macmini",    "pc"),
    ("macpro",     "pc"),
    ("imac",       "pc"),
    # 서버
    ("server",     "server"),
    ("srv-",       "server"),
    ("dc-",        "server"),
    ("pve",        "server"),   # Proxmox
]

# 멀티홈 벤더: 제품군에 따라 타입이 달라서 다른 단서로 결정
_AMBIGUOUS_VENDORS = {"apple", "samsung", "lg", "hewlett", "hp "}


def classify(
    vendor: str | None,
    os_hint: str | None,
    hostname: str | None,
    hostname_sources: dict | None = None,
) -> str:
    """기기 타입을 추론한다.

    우선순위:
      1. 호스트명 패턴 (가장 구체적)
      2. OS 힌트 (TCP 핑거프린팅)
      3. 벤더(OUI) 키워드 (단, 멀티홈 벤더는 OS/hostname 단서가 없을 때만 적용)

    Args:
        vendor:           OUI 조회로 얻은 제조사 이름
        os_hint:          TCP 핑거프린팅 결과 (예: 'windows', 'linux', 'ios')
        hostname:         기기 호스트명 (reverse_dns 포함 최우선 이름)
        hostname_sources: 모든 소스의 호스트명 dict — best_name 선택 외 추가 단서

    Returns:
        'pc' | 'mobile' | 'printer' | 'router' | 'nas' | 'server' | 'iot' | 'unknown'
    """
    # 호스트명 후보 수집 (hostname + hostname_sources의 모든 값)
    name_candidates: list[str] = []
    if hostname:
        name_candidates.append(hostname.lower())
    if hostname_sources:
        for entry in hostname_sources.values():
            n = entry.get("name", "") if isinstance(entry, dict) else ""
            if n:
                name_candidates.append(n.lower())

    # 1. 호스트명 패턴
    for candidate in name_candidates:
        for pattern, device_type in _HOSTNAME_RULES:
            if pattern in candidate:
                return device_type

    # 2. OS 힌트
    if os_hint:
        os_lower = os_hint.lower()
        for prefix, device_type in _OS_RULES:
            if os_lower.startswith(prefix):
                return device_type

    # 3. 벤더 키워드
    if vendor:
        vendor_lower = vendor.lower()
        # 멀티홈 벤더 — 다른 단서 없으면 unknown
        if any(v in vendor_lower for v in _AMBIGUOUS_VENDORS):
            return "unknown"
        for keyword, device_type in _VENDOR_RULES:
            if keyword in vendor_lower:
                return device_type

    return "unknown"


def should_update(current: str, new: str) -> bool:
    """새 타입이 현재 타입보다 구체적인 경우에만 True를 반환한다.

    'unknown'은 항상 더 구체적인 타입으로 덮어쓸 수 있다.
    이미 구체적인 타입이 있으면 'unknown'으로 되돌리지 않는다.
    """
    if new == "unknown":
        return False
    if current == "unknown":
        return True
    # 둘 다 구체적이면 새 타입으로 갱신 (더 최신 정보)
    return new != current
