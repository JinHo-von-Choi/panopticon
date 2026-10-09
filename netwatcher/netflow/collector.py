"""FlowCollector — asyncio UDP 기반 NetFlow/IPFIX 수신기."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from netwatcher.netflow.parser import parse_netflow
from netwatcher.netflow.processor import FlowProcessor

if TYPE_CHECKING:
    pass

logger = logging.getLogger("netwatcher.netflow.collector")


class _FlowProtocol(asyncio.DatagramProtocol):
    """asyncio UDP DatagramProtocol — 수신된 데이터그램을 FlowProcessor에 전달한다."""

    def __init__(self, processor: FlowProcessor) -> None:
        self._processor = processor
        self._accepting = True

    def stop_accepting(self) -> None:
        self._accepting = False

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        logger.debug("NetFlow UDP collector started")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self._accepting:
            return
        flows = parse_netflow(data)
        if flows:
            self._processor.on_flows(flows)

    def error_received(self, exc: Exception) -> None:
        logger.warning("NetFlow UDP error from router: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("NetFlow UDP collector stopped")


class FlowCollector:
    """NetFlow/IPFIX UDP 패킷을 수신하여 FlowProcessor로 전달하는 서비스.

    app.py에서 start() / stop()으로 수명주기를 관리한다.
    """

    def __init__(
        self,
        processor: FlowProcessor,
        host: str = "0.0.0.0",
        port: int = 2055,
    ) -> None:
        self._processor  = processor
        self._host       = host
        self._port       = port
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _FlowProtocol | None = None

    async def start(self) -> None:
        """UDP 소켓을 열고 수신을 시작한다."""
        loop = asyncio.get_running_loop()
        protocol = _FlowProtocol(self._processor)
        self._protocol = protocol
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(self._host, self._port),
        )
        self._transport = transport
        logger.info(
            "NetFlow collector listening on %s:%d", self._host, self._port
        )

    def stop_accepting(self) -> None:
        """소켓 정리 전에도 대기 중인 데이터그램을 분석하지 않는다."""
        if self._protocol is not None:
            self._protocol.stop_accepting()

    def stop(self) -> None:
        """UDP 소켓을 닫는다."""
        self.stop_accepting()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            logger.info("NetFlow collector stopped")
