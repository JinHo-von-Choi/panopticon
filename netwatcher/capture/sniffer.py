"""배압 제어 기능을 갖춘 AsyncSniffer 래퍼."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Callable

from scapy.all import AsyncSniffer, Packet

from netwatcher.capture.filters import build_bpf_filter
from netwatcher.utils.config import Config

logger = logging.getLogger("netwatcher.capture.sniffer")


class PacketSniffer:
    """Scapy AsyncSniffer를 스레드 안전한 asyncio 큐 브릿지로 래핑한다.

    asyncio 루프가 패킷 도착 속도를 따라잡지 못할 때 배압을 적용하기 위해
    크기 제한이 있는 deque 버퍼를 사용한다.
    """

    def __init__(
        self,
        config: Config,
        loop: asyncio.AbstractEventLoop,
        packet_callback: Callable[[Packet], None],
    ) -> None:
        """패킷 스니퍼를 초기화한다. 인터페이스, BPF 필터, 배압 버퍼를 설정한다."""
        self._config          = config
        self._loop            = loop
        self._packet_callback = packet_callback
        self._sniffer: AsyncSniffer | None = None

        self._iface     = config.get("interface")
        self._promisc   = config.get("promiscuous", True)
        self._extra_bpf = config.get("bpf_filter", "")

        # 배압 제어 버퍼
        self._packet_buffer: deque[Packet] = deque(maxlen=50000)
        self._dropped_count = 0
        self._drain_scheduled = False

    @property
    def dropped_count(self) -> int:
        """배압으로 인해 드롭된 패킷의 누적 수를 반환한다."""
        return self._dropped_count

    @property
    def is_running(self) -> bool:
        """스니퍼가 현재 실행 중인지 여부를 반환한다."""
        return self._sniffer is not None and self._sniffer.running

    def _on_packet(self, pkt: Packet) -> None:
        """스니퍼 스레드에서 호출됨; 크기 제한 버퍼를 통해 asyncio 루프로 브릿지한다."""
        if len(self._packet_buffer) >= self._packet_buffer.maxlen:
            self._dropped_count += 1
            return
        self._packet_buffer.append(pkt)
        if not self._drain_scheduled:
            self._drain_scheduled = True
            try:
                self._loop.call_soon_threadsafe(self._drain_buffer)
            except RuntimeError:
                pass  # 루프 종료됨

    def _drain_buffer(self) -> None:
        """버퍼링된 패킷을 패킷 콜백으로 배출한다 (asyncio 루프에서 실행)."""
        self._drain_scheduled = False
        batch_limit = 500  # 배출 주기당 최대 500개 패킷 처리
        for _ in range(batch_limit):
            if not self._packet_buffer:
                break
            try:
                pkt = self._packet_buffer.popleft()
            except IndexError:
                break
            self._packet_callback(pkt)
        # 아직 남은 패킷이 있으면 다음 배출을 스케줄링
        if self._packet_buffer:
            self._drain_scheduled = True
            try:
                self._loop.call_soon_threadsafe(self._drain_buffer)
            except RuntimeError:
                pass

    def start(self) -> None:
        """백그라운드 스레드에서 패킷 스니퍼를 시작한다."""
        bpf = build_bpf_filter(self._extra_bpf)
        logger.info(
            "Starting sniffer on iface=%s promisc=%s bpf='%s'",
            self._iface or "auto",
            self._promisc,
            bpf,
        )

        kwargs = {
            "prn": self._on_packet,
            "store": False,
            "promisc": self._promisc,
        }
        if self._iface:
            kwargs["iface"] = self._iface
        if bpf:
            kwargs["filter"] = bpf

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        logger.info("Sniffer started")

    def stop(self) -> None:
        """스니퍼를 중지한다."""
        if self._sniffer:
            self._sniffer.stop()
            if self._dropped_count > 0:
                logger.warning(
                    "Sniffer stopped. Total dropped packets: %d", self._dropped_count
                )
            else:
                logger.info("Sniffer stopped")
