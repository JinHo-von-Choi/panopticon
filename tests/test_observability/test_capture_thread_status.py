"""실제 Scapy 스레드가 종료됐을 때 상태와 정리 동작을 확인한다."""

import asyncio

import pytest
from scapy.sendrecv import AsyncSniffer

from netwatcher.capture.sniffer import PacketSniffer
from netwatcher.utils.config import Config


@pytest.mark.parametrize("failed", [True, False])
def test_finished_capture_thread_is_not_running_and_can_be_stopped(monkeypatch, failed):
    def run(backend, **kwargs):
        backend.running = True
        if failed:
            raise PermissionError("capture denied")

    monkeypatch.setattr(AsyncSniffer, "_run", run)
    loop = asyncio.new_event_loop()
    try:
        capture = PacketSniffer(Config({}), loop, lambda packet: None)
        capture.start()
        backend = capture._sniffer
        backend.thread.join(timeout=2)
        assert not backend.thread.is_alive()
        assert backend.running  # Scapy의 플래그는 종료된 스레드에서도 남는다.
        assert isinstance(backend.exception, PermissionError) if failed else backend.exception is None
        assert capture.is_running is False
        capture.stop()
    finally:
        loop.close()
