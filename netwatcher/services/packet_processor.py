"""PacketProcessor - 패킷 콜백, 트래픽 카운터, 디바이스 버퍼, 엔진 디스패치."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from scapy.all import ARP, DNS, TCP, UDP, Packet

from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs
from netwatcher.inventory import hostname_resolver, port_tracker
from netwatcher.utils.geoip import enrich_alert_metadata
from netwatcher.utils.network import mac_vendor_lookup
from netwatcher.utils.packet_info import extract_packet_info, guess_os

try:
    from netwatcher.web.metrics import packets_total as _packets_total
except ImportError:
    _packets_total = None

if TYPE_CHECKING:
    from netwatcher.alerts.dispatcher import AlertDispatcher
    from netwatcher.capture.pcap_writer import PCAPWriter
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.utils.network import AsyncDNSResolver

logger = logging.getLogger("netwatcher.services.packet_processor")


def _utc_now_iso() -> str:
    """현재 UTC 시각을 ISO 8601 문자열로 반환한다."""
    return datetime.now(timezone.utc).isoformat()


class PacketProcessor:
    """패킷별 콜백, 트래픽 카운터, 디바이스 버퍼를 소유한다."""

    def __init__(
        self,
        registry: EngineRegistry,
        dispatcher: AlertDispatcher | None,
        pcap_writer: PCAPWriter,
        dns_resolver: AsyncDNSResolver,
    ) -> None:
        """패킷 프로세서를 초기화한다. 레지스트리, 디스패처, PCAP 기록기 등을 주입받는다."""
        self.registry     = registry
        self.dispatcher   = dispatcher
        self.pcap_writer  = pcap_writer
        self._dns_resolver = dns_resolver

        # 트래픽 카운터 (플러시 간격 단위)
        self._pkt_count  = 0
        self._byte_count = 0
        self._tcp_count  = 0
        self._udp_count  = 0
        self._arp_count  = 0
        self._dns_count  = 0

        # 디바이스 배치 버퍼
        self._device_buffer: dict[str, dict] = {}

        # 신규 기기 감지 캐시 — app.py 기동 시 init_seen_macs()로 초기화
        self._seen_macs: set[str] = set()

    async def init_seen_macs(self, device_repo: object) -> None:
        """DB에 이미 존재하는 MAC 주소를 캐시에 로드한다.

        최초 실행 시 기존 디바이스를 '새 기기'로 잘못 알리지 않도록
        app.py의 run()에서 PacketProcessor 생성 직후 호출해야 한다.
        """
        macs = await device_repo.get_all_macs()  # type: ignore[attr-defined]
        self._seen_macs.update(macs)
        logger.info("Loaded %d existing MACs into seen-macs cache", len(macs))

    def on_packet(self, packet: Packet) -> None:
        """스니퍼 스레드의 콜백, call_soon_threadsafe를 통해 디스패치된다."""
        # 트래픽 카운터 업데이트
        self._pkt_count += 1
        pkt_len = len(packet)
        self._byte_count += pkt_len

        # Prometheus 패킷 카운터
        if _packets_total is not None:
            _packets_total.inc()

        if packet.haslayer(TCP):
            self._tcp_count += 1
        if packet.haslayer(UDP):
            self._udp_count += 1
        if packet.haslayer(ARP):
            self._arp_count += 1
        if packet.haslayer(DNS):
            self._dns_count += 1

        # PCAP 링 버퍼에 추가
        self.pcap_writer.add_packet(packet)

        # 출발지 정보 추출
        src_mac = getattr(packet, "src", None)
        src_ip  = None
        src_ip_pkt, _ = get_ip_addrs(packet)
        if src_ip_pkt:
            src_ip = src_ip_pkt
        elif packet.haslayer(ARP):
            src_ip  = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

        # 보강: 벤더 + 호스트명 (비동기, 논블로킹) + OS 힌트
        vendor   = mac_vendor_lookup(src_mac) if src_mac else None
        hostname = None
        os_hint  = None
        if src_ip:
            hostname = self._dns_resolver.lookup(src_ip)
            os_hint  = guess_os(packet)

        # 메모리 버퍼에 디바이스 정보 축적 (주기적으로 일괄 플러시)
        if src_mac:
            buf = self._device_buffer.setdefault(src_mac, {"bytes": 0, "packets": 0})
            buf["ip"]       = src_ip
            buf["hostname"] = hostname
            buf["vendor"]   = vendor
            buf["os_hint"]  = os_hint
            buf["bytes"]   += pkt_len
            buf["packets"] += 1

            # 신규 기기 감지
            if src_mac not in self._seen_macs:
                self._seen_macs.add(src_mac)
                self._fire_new_device_alert(src_mac, src_ip, vendor)

        # 패시브 호스트명 수집 (DHCP/NetBIOS/mDNS/LLMNR)
        for hit in hostname_resolver.extract(packet):
            hit_buf = self._device_buffer.setdefault(
                hit.mac, {"bytes": 0, "packets": 0},
            )
            sources: dict = hit_buf.setdefault("hostname_sources", {})
            sources[hit.source] = {"name": hit.name, "updated": _utc_now_iso()}
            # 소스에서 IP를 얻었고 버퍼에 아직 IP가 없는 경우 보완
            if hit.ip and not hit_buf.get("ip"):
                hit_buf["ip"] = hit.ip

        # 패시브 포트 탐지 (TCP SYN-ACK 관찰)
        for phit in port_tracker.extract(packet):
            phit_buf = self._device_buffer.setdefault(
                phit.mac, {"bytes": 0, "packets": 0},
            )
            open_ports: set[int] = phit_buf.setdefault("open_ports", set())
            open_ports.add(phit.port)

        # 탐지 엔진 실행
        alerts = self.registry.process_packet(packet)
        for alert in alerts:
            alert.packet_info = extract_packet_info(packet)
            enrich_alert_metadata(alert.metadata, alert.source_ip, alert.dest_ip)
            if self.dispatcher:
                self.dispatcher.enqueue(alert)

    def snapshot_and_reset_counters(self) -> dict[str, int]:
        """현재 카운터 값을 반환하고 0으로 초기화한다.

        on_packet과 같은 이벤트 루프에서 호출해야 한다 (락 불필요).
        """
        snapshot = {
            "total_packets": self._pkt_count,
            "total_bytes":   self._byte_count,
            "tcp_count":     self._tcp_count,
            "udp_count":     self._udp_count,
            "arp_count":     self._arp_count,
            "dns_count":     self._dns_count,
        }
        self._pkt_count = self._byte_count = 0
        self._tcp_count = self._udp_count  = 0
        self._arp_count = self._dns_count   = 0
        return snapshot

    def _fire_new_device_alert(
        self,
        mac: str,
        ip: str | None,
        vendor: str | None,
    ) -> None:
        """처음 관찰된 기기에 대한 알림을 디스패처에 큐잉한다."""
        if not self.dispatcher:
            return
        vendor_str = vendor or "알 수 없음"
        ip_str     = ip     or "알 수 없음"
        alert = Alert(
            engine      = "asset_inventory",
            severity    = Severity.WARNING,
            title       = "New Device Detected",
            description = (
                f"미등록 기기가 네트워크에 나타났습니다. "
                f"MAC: {mac}  제조사: {vendor_str}  IP: {ip_str}. "
                f"인가된 기기인지 확인하고 'is_known'으로 등록하세요."
            ),
            source_mac  = mac,
            source_ip   = ip,
            confidence  = 0.9,
            metadata    = {"vendor": vendor_str, "ip": ip_str},
        )
        self.dispatcher.enqueue(alert)

    def drain_device_buffer(self) -> dict[str, dict]:
        """축적된 디바이스 버퍼를 반환하고 비운다."""
        batch = self._device_buffer.copy()
        self._device_buffer.clear()
        return batch
