"""배압 제어 기능을 갖춘 AsyncSniffer 래퍼."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from typing import TYPE_CHECKING, Callable

from scapy.all import AsyncSniffer, Packet

from netwatcher.capture.filters import build_bpf_filter
from netwatcher.observability.observation import (
    DROP_SOURCE_APP,
    KIND_DROPPED,
    KIND_RECEIVED,
    STAGE_CAPTURE,
    STAGE_INPUT_QUEUE,
    KernelDropProbe,
)
from netwatcher.utils.config import Config

if TYPE_CHECKING:
    from netwatcher.observability.observation import ObservationService

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
        observation: "ObservationService | None" = None,
        kernel_probe: "KernelDropProbe | None" = None,
    ) -> None:
        """패킷 스니퍼를 초기화한다. 인터페이스, BPF 필터, 배압 버퍼를 설정한다."""
        self._config          = config
        self._loop            = loop
        self._packet_callback = packet_callback
        self._sniffer: AsyncSniffer | None = None
        self._observation     = observation

        self._iface     = config.get("interface")
        self._promisc   = config.get("promiscuous", True)
        self._extra_bpf = config.get("bpf_filter", "")

        # 배압 제어 버퍼
        self._packet_buffer: deque[Packet] = deque(maxlen=50000)
        self._dropped_count = 0
        self._drain_scheduled = False

        # 커널(softnet) drop 측정 — capture 단계 손실의 다른 주체 (계획서 3장).
        # 대시보드가 같은 프로브의 지원 여부를 함께 보여주므로 주입 가능하게 한다.
        self.kernel_probe = kernel_probe or KernelDropProbe(observation)

        # 관측 계측 배치 카운터. 패킷마다 잠그면 고속 경로에서 계측이 본체가
        # 되므로, 스니퍼 스레드에 합산해 두고 asyncio 루프에서 한 번에 반영한다.
        self._obs_lock = threading.Lock()
        self._obs_capture_received = 0
        self._obs_queue_received = 0
        self._obs_queue_dropped = 0

    @property
    def observation(self) -> "ObservationService | None":
        return self._observation

    def set_observation(self, observation: "ObservationService | None") -> None:
        """관측 서비스를 나중에 주입한다."""
        self._observation = observation
        self.kernel_probe = KernelDropProbe(observation)

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
        with self._obs_lock:
            self._obs_capture_received += 1
        if len(self._packet_buffer) >= self._packet_buffer.maxlen:
            self._dropped_count += 1
            # 버퍼가 가득 찬 것은 앱 결정이다. 커널 drop 과 합산하지 않는다.
            with self._obs_lock:
                self._obs_queue_dropped += 1
            return
        self._packet_buffer.append(pkt)
        with self._obs_lock:
            self._obs_queue_received += 1
        if not self._drain_scheduled:
            self._drain_scheduled = True
            try:
                self._loop.call_soon_threadsafe(self._drain_buffer)
            except RuntimeError:
                pass  # 루프 종료됨

    def flush_observation(self) -> None:
        """스니퍼 스레드가 쌓은 계측값을 관측 서비스로 한 번에 반영한다.

        asyncio 루프에서만 호출된다. 스왑 후 0 으로 만들기 때문에, 반영 중
        도착한 패킷이 다음 배치로 넘어갈 뿐 유실되지 않는다.
        """
        observation = self._observation
        if observation is None:
            return
        with self._obs_lock:
            capture_received = self._obs_capture_received
            queue_received = self._obs_queue_received
            queue_dropped = self._obs_queue_dropped
            self._obs_capture_received = 0
            self._obs_queue_received = 0
            self._obs_queue_dropped = 0

        if capture_received:
            observation.record(STAGE_CAPTURE, KIND_RECEIVED, capture_received)
        if queue_received:
            observation.record(STAGE_INPUT_QUEUE, KIND_RECEIVED, queue_received)
        if queue_dropped:
            observation.record(
                STAGE_INPUT_QUEUE, KIND_DROPPED, queue_dropped, drop_source=DROP_SOURCE_APP,
            )

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
        # 계측은 배출 성공 여부와 무관하게 항상 반영한다
        self.flush_observation()
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
        self.flush_observation()
        if self._sniffer:
            self._sniffer.stop()
            if self._dropped_count > 0:
                logger.warning(
                    "Sniffer stopped. Total dropped packets: %d", self._dropped_count
                )
            else:
                logger.info("Sniffer stopped")
