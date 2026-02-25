"""디바이스 위험도 점수 산정 모듈 (순수 함수, I/O 없음)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

# 고위험 서비스 포트: 인증 없이 노출 시 즉각적 위협이 되는 포트
_DANGEROUS_PORTS: frozenset[int] = frozenset({
    21,    # FTP     — 평문 자격증명
    23,    # Telnet  — 평문 세션
    69,    # TFTP    — 인증 없는 파일 전송
    161,   # SNMP    — 설정 노출
    2375,  # Docker  — API 무인증 접근
    3389,  # RDP     — 원격 데스크톱
    5900,  # VNC     — 원격 데스크톱
})

_DANGEROUS_SCORE_PER_PORT = 15
_DANGEROUS_SCORE_CAP      = 40

_MANY_PORTS_THRESHOLD = 5
_NEW_DEVICE_HOURS     = 24


class RiskFactor(NamedTuple):
    """개별 위험 요소."""

    name:  str
    score: int
    note:  str


class RiskAssessment(NamedTuple):
    """디바이스 위험도 평가 결과."""

    score:   int              # 0–100
    level:   str              # "low" | "medium" | "high"
    factors: list[RiskFactor]


def _level(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def assess(device: dict) -> RiskAssessment:
    """디바이스 dict를 받아 위험도를 평가한다.

    순수 함수 — DB 호출 없음.  모든 입력은 DeviceRepository.list_all()이
    반환하는 필드에 의존한다.

    위험 요인:
      - 미등록 기기 (is_known=False): +20
      - 기기 타입 불명 (device_type="unknown"): +10
      - 호스트명 없음: +8
      - 고위험 개방 포트 (포트당 +15, 최대 +40)
      - 개방 포트 과다 (>5개): +10
      - 신규 기기 (첫 발견 24시간 미만): +10
    총점은 100에서 클램핑된다.
    """
    factors: list[RiskFactor] = []
    total   = 0

    # 미등록 기기
    if not device.get("is_known"):
        s = 20
        factors.append(RiskFactor("unregistered", s, "인가되지 않은 기기"))
        total += s

    # 기기 타입 미분류
    if (device.get("device_type") or "unknown") == "unknown":
        s = 10
        factors.append(RiskFactor("unknown_type", s, "기기 유형 미식별"))
        total += s

    # 호스트명 없음
    hostname = (device.get("hostname") or "").strip()
    if not hostname or hostname.lower() == "n/a":
        s = 8
        factors.append(RiskFactor("no_hostname", s, "호스트명 미확인"))
        total += s

    # 고위험 개방 포트
    open_ports   = device.get("open_ports") or []
    danger_found = [p for p in open_ports if p in _DANGEROUS_PORTS]
    if danger_found:
        raw = len(danger_found) * _DANGEROUS_SCORE_PER_PORT
        s   = min(raw, _DANGEROUS_SCORE_CAP)
        factors.append(RiskFactor(
            "dangerous_ports", s,
            "고위험 포트 개방: " + ", ".join(str(p) for p in sorted(danger_found)),
        ))
        total += s

    # 개방 포트 과다
    if len(open_ports) > _MANY_PORTS_THRESHOLD:
        s = 10
        factors.append(RiskFactor(
            "many_ports", s,
            f"개방 포트 {len(open_ports)}개 (임계값 {_MANY_PORTS_THRESHOLD}개 초과)",
        ))
        total += s

    # 신규 기기
    first_seen_raw = device.get("first_seen")
    if first_seen_raw:
        try:
            if isinstance(first_seen_raw, str):
                # ISO 8601 문자열 파싱 (Python 3.10 이하 호환)
                first_seen_raw = first_seen_raw.replace("Z", "+00:00")
                fs = datetime.fromisoformat(first_seen_raw)
            else:
                fs = first_seen_raw  # datetime 객체
            if fs.tzinfo is None:
                fs = fs.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - fs).total_seconds() / 3600
            if age_hours < _NEW_DEVICE_HOURS:
                s = 10
                factors.append(RiskFactor("new_device", s, f"첫 발견 후 {age_hours:.1f}시간 경과"))
                total += s
        except (ValueError, TypeError):
            pass

    clamped = min(total, 100)
    return RiskAssessment(score=clamped, level=_level(clamped), factors=list(factors))
