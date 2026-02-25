"""알림 발생 시 포렌식 패킷 캡처를 위한 PCAP 파일 기록기."""

from __future__ import annotations

import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Any

from scapy.all import IP, Packet, wrpcap

logger = logging.getLogger("netwatcher.capture.pcap_writer")


class PCAPWriter:
    """최근 패킷의 ring buffer를 유지하고 요청 시 PCAP 파일을 기록한다.

    알림 발생 시, 시간 윈도우 내에서 src/dst가 일치하는 관련 패킷을
    포렌식 분석용 PCAP 파일로 저장한다.
    """

    def __init__(
        self,
        output_dir: str = "data/pcaps",
        buffer_size: int = 1000,
        context_seconds: float = 5.0,
        max_storage_mb: int = 500,
    ) -> None:
        """PCAP 기록기를 초기화한다. 출력 디렉토리, 버퍼 크기, 저장 제한을 설정한다."""
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._buffer_size = buffer_size
        self._context_seconds = context_seconds
        self._max_storage_bytes = max_storage_mb * 1024 * 1024

        # Ring buffer: (타임스탬프, 패킷) 쌍의 deque
        self._buffer: deque[tuple[float, Packet]] = deque(maxlen=buffer_size)

    def add_packet(self, packet: Packet) -> None:
        """패킷을 ring buffer에 추가한다."""
        self._buffer.append((time.time(), packet))

    def capture_for_alert(
        self,
        event_id: int,
        source_ip: str | None,
        dest_ip: str | None,
        alert_timestamp: float | None = None,
    ) -> str | None:
        """알림 관련 패킷이 포함된 PCAP 파일을 기록한다.

        패킷이 캡처되면 파일 경로를 반환하고, 없으면 None을 반환한다.
        """
        if not source_ip and not dest_ip:
            return None

        now = alert_timestamp or time.time()
        window_start = now - self._context_seconds
        window_end = now + self._context_seconds

        # 일치하는 패킷 필터링
        matching = []
        for ts, pkt in self._buffer:
            if ts < window_start or ts > window_end:
                continue
            if pkt.haslayer(IP):
                pkt_src = pkt[IP].src
                pkt_dst = pkt[IP].dst
                if (
                    (source_ip and (pkt_src == source_ip or pkt_dst == source_ip))
                    or (dest_ip and (pkt_src == dest_ip or pkt_dst == dest_ip))
                ):
                    matching.append(pkt)

        if not matching:
            return None

        filename = f"event_{event_id}_{int(now)}.pcap"
        filepath = self._output_dir / filename

        try:
            wrpcap(str(filepath), matching)
            logger.info(
                "PCAP captured: %s (%d packets)", filename, len(matching)
            )

            # 저장 용량 제한 적용
            self._enforce_storage_limit()

            return str(filepath)
        except Exception:
            logger.exception("Failed to write PCAP: %s", filename)
            return None

    def _enforce_storage_limit(self) -> None:
        """전체 저장 용량이 제한을 초과하면 가장 오래된 PCAP 파일을 삭제한다."""
        try:
            pcap_files = sorted(
                self._output_dir.glob("*.pcap"),
                key=lambda p: p.stat().st_mtime,
            )
            total_size = sum(f.stat().st_size for f in pcap_files)

            while total_size > self._max_storage_bytes and pcap_files:
                oldest = pcap_files.pop(0)
                total_size -= oldest.stat().st_size
                oldest.unlink()
                logger.info("Deleted old PCAP: %s", oldest.name)
        except Exception:
            logger.exception("Error enforcing PCAP storage limit")

    def get_pcap_path(self, event_id: int) -> str | None:
        """이벤트 ID에 해당하는 PCAP 파일을 찾는다."""
        for f in self._output_dir.glob(f"event_{event_id}_*.pcap"):
            return str(f)
        return None
