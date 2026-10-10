"""EVE 기록을 위협 피드와 대조한다. 대조만 하고 경보나 차단은 만들지 않는다."""

from __future__ import annotations

MAX_MATCHES = 4
MAX_NAME_LENGTH = 253


def feed_matches(record: dict, names: dict, feeds) -> list[dict]:
    """주소와 도메인 이름이 피드에 있으면 근거를 돌려준다.

    names는 저장하지 않는 원본 필드(DNS 질의 이름, TLS SNI)다. 일치한 지표만 결과에 남는다.
    """
    candidates = [("ip", field, record.get(field)) for field in ("src_ip", "dest_ip")]
    candidates += [("domain", field, value) for field, value in names.items()
                   if isinstance(value, str) and 0 < len(value) <= MAX_NAME_LENGTH]
    matches = []
    for kind, field, value in candidates:
        if not value:
            continue
        found = feeds.match_ip(value) if kind == "ip" else feeds.match_domain(value)
        if found:
            matches.append({"field": field, "indicator": value, "source": found.get("source")})
            if len(matches) == MAX_MATCHES:
                break
    return matches
