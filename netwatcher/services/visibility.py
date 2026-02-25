"""네트워크 가시성 상태 — 공유 인메모리 싱글턴.

PacketProcessor가 플러시 주기마다 갱신하고,
stats 라우트가 읽어 대시보드에 노출한다.
"""

from __future__ import annotations


class _VisibilityState:
    """플러시 윈도우별 네트워크 가시성 지표를 보관하는 단순 컨테이너."""

    def __init__(self) -> None:
        self.distinct_src_macs: int  = 0   # 직전 윈도우에서 관찰된 고유 source MAC 수
        self.total_packets:     int  = 0   # 직전 윈도우 총 패킷 수

    def update(self, distinct_src_macs: int, total_packets: int) -> None:
        """StatsFlushService의 플러시 루프에서 호출한다."""
        self.distinct_src_macs = distinct_src_macs
        self.total_packets     = total_packets

    def to_dict(self) -> dict:
        """stats 라우트가 직렬화에 사용한다."""
        macs = self.distinct_src_macs

        # 가시성 수준 판정
        # SPAN 없는 스위치 환경: 자신 + 게이트웨이(ARP) → 보통 1~2개 MAC
        # SPAN 있음: 다수의 서로 다른 호스트 트래픽 → 다양한 MAC
        if macs <= 2:
            level = "none"      # SPAN 미감지
        elif macs <= 8:
            level = "partial"   # 일부 트래픽만 가시
        else:
            level = "full"      # SPAN 정상 동작 추정

        return {
            "distinct_src_macs": macs,
            "total_packets":     self.total_packets,
            "level":             level,
        }


# 프로세스 전역 싱글턴
state: _VisibilityState = _VisibilityState()
