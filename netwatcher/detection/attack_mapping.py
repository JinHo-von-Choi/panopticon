"""MITRE ATT&CK TTP 레지스트리 및 Kill Chain 매핑.

각 TTP 코드를 구조화된 메타데이터(전술, 기법명, Kill Chain 단계)로 변환한다.
엔진은 `mitre_attack_ids` 클래스 속성에 TTP를 선언하고, 이 모듈을 통해
표준화된 분류 체계를 활용한다.
"""

from __future__ import annotations

from dataclasses import dataclass


# Kill Chain 단계 상수
RECONNAISSANCE       = "reconnaissance"
RESOURCE_DEVELOPMENT = "resource_development"
INITIAL_ACCESS       = "initial_access"
EXECUTION            = "execution"
PERSISTENCE          = "persistence"
PRIVILEGE_ESCALATION = "privilege_escalation"
DEFENSE_EVASION      = "defense_evasion"
CREDENTIAL_ACCESS    = "credential_access"
DISCOVERY            = "discovery"
LATERAL_MOVEMENT     = "lateral_movement"
COLLECTION           = "collection"
COMMAND_AND_CONTROL  = "command_and_control"
EXFILTRATION         = "exfiltration"
IMPACT               = "impact"

# Kill Chain 단계 진행 순서 (낮은 인덱스 = 초기 단계)
KILL_CHAIN_ORDER: list[str] = [
    RECONNAISSANCE,
    RESOURCE_DEVELOPMENT,
    INITIAL_ACCESS,
    EXECUTION,
    PERSISTENCE,
    PRIVILEGE_ESCALATION,
    DEFENSE_EVASION,
    CREDENTIAL_ACCESS,
    DISCOVERY,
    LATERAL_MOVEMENT,
    COLLECTION,
    COMMAND_AND_CONTROL,
    EXFILTRATION,
    IMPACT,
]


@dataclass(frozen=True)
class TTPInfo:
    """단일 MITRE ATT&CK TTP 항목."""
    id: str               # 예: "T1046"
    name: str             # 기법명
    tactic: str           # ATT&CK 전술명 (영문 소문자)
    kill_chain_phase: str # KILL_CHAIN_ORDER 중 하나
    description: str      # 한 줄 설명


# ---------------------------------------------------------------------------
# TTP 레지스트리 — 프로젝트 엔진에서 사용하는 TTP를 포함한 상위 집합
# ---------------------------------------------------------------------------
_REGISTRY_ENTRIES: list[TTPInfo] = [
    # Reconnaissance
    TTPInfo("T1046",     "Network Service Discovery",          "discovery",            DISCOVERY,            "포트 스캔으로 활성 서비스 식별"),
    TTPInfo("T1018",     "Remote System Discovery",            "discovery",            DISCOVERY,            "내부 IP 스캔으로 호스트 열거"),
    TTPInfo("T1595",     "Active Scanning",                    "reconnaissance",       RECONNAISSANCE,       "외부 공격자의 능동적 네트워크 스캔"),
    TTPInfo("T1590",     "Gather Victim Network Information",  "reconnaissance",       RECONNAISSANCE,       "네트워크 정보 수집"),

    # Initial Access
    TTPInfo("T1190",     "Exploit Public-Facing Application",  "initial_access",       INITIAL_ACCESS,       "공개 서비스 취약점 익스플로잇"),
    TTPInfo("T1133",     "External Remote Services",           "initial_access",       INITIAL_ACCESS,       "외부 원격 서비스 악용"),

    # Defense Evasion
    TTPInfo("T1036",     "Masquerading",                       "defense_evasion",      DEFENSE_EVASION,      "정상 프로세스·파일로 위장"),
    TTPInfo("T1036.005", "Match Legitimate Name or Location",  "defense_evasion",      DEFENSE_EVASION,      "MAC 스푸핑 등 정상 식별자 모방"),

    # Credential Access
    TTPInfo("T1557",     "Adversary-in-the-Middle",            "credential_access",    CREDENTIAL_ACCESS,    "중간자 공격으로 자격 증명 탈취"),
    TTPInfo("T1557.002", "ARP Cache Poisoning",                "credential_access",    CREDENTIAL_ACCESS,    "ARP 스푸핑으로 트래픽 가로채기"),
    TTPInfo("T1557.003", "DHCP Spoofing",                      "credential_access",    CREDENTIAL_ACCESS,    "DHCP 스푸핑으로 기본 게이트웨이 교체"),

    # Lateral Movement
    TTPInfo("T1021",     "Remote Services",                    "lateral_movement",     LATERAL_MOVEMENT,     "원격 서비스를 통한 내부 이동"),
    TTPInfo("T1599",     "Network Boundary Bridging",          "lateral_movement",     LATERAL_MOVEMENT,     "네트워크 세그먼트 경계 우회"),

    # Collection
    TTPInfo("T1030",     "Data Transfer Size Limits",          "exfiltration",         EXFILTRATION,         "데이터 전송량 한도 초과"),
    TTPInfo("T1041",     "Exfiltration Over C2 Channel",       "exfiltration",         EXFILTRATION,         "C2 채널을 통한 데이터 유출"),
    TTPInfo("T1048",     "Exfiltration Over Alternative Protocol", "exfiltration",     EXFILTRATION,         "비정상 프로토콜 경유 데이터 유출"),

    # Command and Control
    TTPInfo("T1071",     "Application Layer Protocol",         "command_and_control",  COMMAND_AND_CONTROL,  "표준 애플리케이션 프로토콜 경유 C2"),
    TTPInfo("T1071.001", "Web Protocols",                      "command_and_control",  COMMAND_AND_CONTROL,  "HTTP/HTTPS 경유 C2"),
    TTPInfo("T1071.004", "DNS",                                "command_and_control",  COMMAND_AND_CONTROL,  "DNS 경유 C2"),
    TTPInfo("T1573",     "Encrypted Channel",                  "command_and_control",  COMMAND_AND_CONTROL,  "암호화 채널 경유 C2"),
    TTPInfo("T1571",     "Non-Standard Port",                  "command_and_control",  COMMAND_AND_CONTROL,  "비표준 포트 경유 C2"),
    TTPInfo("T1568",     "Dynamic Resolution",                 "command_and_control",  COMMAND_AND_CONTROL,  "Fast Flux 등 동적 DNS 해석"),

    # Impact
    TTPInfo("T1486",     "Data Encrypted for Impact",          "impact",               IMPACT,               "랜섬웨어 파일 암호화"),
    TTPInfo("T1498",     "Network Denial of Service",          "impact",               IMPACT,               "서비스 거부 공격"),
]

# ID → TTPInfo 조회 테이블
TTP_REGISTRY: dict[str, TTPInfo] = {entry.id: entry for entry in _REGISTRY_ENTRIES}


# ---------------------------------------------------------------------------
# 공개 API
# ---------------------------------------------------------------------------

def get_ttp(ttp_id: str) -> TTPInfo | None:
    """TTP ID로 TTPInfo를 조회한다. 없으면 None을 반환한다.

    부분 매칭 지원: "T1557.002"가 없으면 기저 "T1557"로 폴백한다.
    """
    info = TTP_REGISTRY.get(ttp_id)
    if info is not None:
        return info
    # 서브테크닉 폴백: T1557.002 → T1557
    base = ttp_id.split(".")[0]
    return TTP_REGISTRY.get(base)


def ttp_to_kill_chain_phase(ttp_id: str) -> str | None:
    """TTP ID를 Kill Chain 단계 문자열로 변환한다. 알 수 없으면 None."""
    info = get_ttp(ttp_id)
    return info.kill_chain_phase if info else None


def enrich_alert_metadata(mitre_attack_id: str | None, metadata: dict) -> dict:
    """mitre_attack_id가 있을 때 metadata에 TTP 정보를 추가하고 반환한다.

    원본 metadata dict를 수정하지 않고 새 dict를 반환한다.
    """
    if not mitre_attack_id:
        return metadata

    info = get_ttp(mitre_attack_id)
    if info is None:
        return metadata

    return {
        **metadata,
        "ttp_name":        info.name,
        "ttp_tactic":      info.tactic,
        "kill_chain_phase": info.kill_chain_phase,
    }
