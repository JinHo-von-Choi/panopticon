"""Tests for passive port tracker (TCP SYN-ACK observation)."""

from scapy.all import ARP, Ether, IP, TCP

from netwatcher.inventory.port_tracker import extract, service_name

_SERVER_MAC = "aa:bb:cc:dd:ee:01"
_CLIENT_MAC = "ff:ee:dd:cc:bb:aa"


def _syn_ack(sport: int, dport: int = 54321) -> Ether:
    """서버가 보내는 SYN-ACK 패킷."""
    return (
        Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
        / IP(src="192.168.1.10", dst="192.168.1.100")
        / TCP(sport=sport, dport=dport, flags="SA")
    )


def _syn(sport: int = 54321, dport: int = 80) -> Ether:
    """클라이언트가 보내는 SYN 패킷."""
    return (
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / TCP(sport=sport, dport=dport, flags="S")
    )


def _ack(sport: int = 54321, dport: int = 80) -> Ether:
    """클라이언트가 보내는 ACK 패킷."""
    return (
        Ether(src=_CLIENT_MAC, dst=_SERVER_MAC)
        / IP() / TCP(sport=sport, dport=dport, flags="A")
    )


class TestExtract:
    def test_syn_ack_returns_port_hit(self):
        pkt  = _syn_ack(sport=80)
        hits = extract(pkt)
        assert len(hits) == 1
        assert hits[0].port == 80
        assert hits[0].mac  == _SERVER_MAC

    def test_syn_only_ignored(self):
        assert extract(_syn()) == []

    def test_ack_only_ignored(self):
        assert extract(_ack()) == []

    def test_non_tcp_packet_ignored(self):
        pkt = Ether() / ARP()
        assert extract(pkt) == []

    def test_ephemeral_port_excluded(self):
        # 49152 이상은 클라이언트 임시 포트로 간주
        assert extract(_syn_ack(sport=49152)) == []
        assert extract(_syn_ack(sport=55000)) == []
        assert extract(_syn_ack(sport=65535)) == []

    def test_boundary_below_ephemeral_included(self):
        # 49151은 ephemeral 경계 미만 → 포함
        hits = extract(_syn_ack(sport=49151))
        assert len(hits) == 1
        assert hits[0].port == 49151

    def test_well_known_ports(self):
        for port in (22, 80, 443, 445, 3389):
            hits = extract(_syn_ack(sport=port))
            assert len(hits) == 1, f"port {port} not detected"
            assert hits[0].port == port

    def test_rst_flag_ignored(self):
        """RST 패킷은 SYN-ACK가 아니므로 무시한다."""
        pkt = (
            Ether(src=_SERVER_MAC, dst=_CLIENT_MAC)
            / IP(src="192.168.1.10", dst="192.168.1.100")
            / TCP(sport=80, dport=54321, flags="R")
        )
        assert extract(pkt) == []


class TestServiceName:
    def test_well_known_services(self):
        assert service_name(22)    == "SSH"
        assert service_name(80)    == "HTTP"
        assert service_name(443)   == "HTTPS"
        assert service_name(445)   == "SMB"
        assert service_name(3306)  == "MySQL"
        assert service_name(3389)  == "RDP"
        assert service_name(5432)  == "PostgreSQL"
        assert service_name(6379)  == "Redis"
        assert service_name(27017) == "MongoDB"

    def test_unknown_port_returns_empty(self):
        assert service_name(9999)  == ""
        assert service_name(12345) == ""
        assert service_name(0)     == ""
