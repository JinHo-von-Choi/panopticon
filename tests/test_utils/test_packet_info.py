"""공통 파싱의 주소 선택·프로토콜·증거 출력 계약."""
from scapy.all import ARP, DNS, DNSQR, Ether, IP, IPv6, Raw, TCP, UDP

from netwatcher.detection.utils import get_ip_addrs
from netwatcher.utils.packet_info import extract_packet_info, guess_os


def ethernet():
    return Ether(src='02:00:00:00:00:10', dst='02:00:00:00:00:20')


def test_ipv4_tcp_http_evidence_and_os_hint():
    packet = ethernet() / IP(src='192.0.2.10', dst='192.0.2.20', ttl=64) / TCP(
        sport=12345, dport=80, flags='PA', window=29200) / Raw(
        b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
    info = extract_packet_info(packet)
    assert get_ip_addrs(packet) == ('192.0.2.10', '192.0.2.20')
    assert info['layers'] == ['Ethernet', 'IP', 'TCP', 'HTTP']
    assert info['src_port'] == 12345
    assert info['tcp_flags_list'] == ['PSH', 'ACK']
    assert info['http_host'] == 'example.invalid'
    assert info['payload_hex'] == bytes(packet[Raw].load).hex()
    assert guess_os(packet) == 'Linux'


def test_ipv6_dns_question_and_no_ipv4_os_guess():
    packet = ethernet() / IPv6(src='2001:db8::10', dst='2001:db8::20') / UDP(
        dport=53) / DNS(qd=DNSQR(qname='example.invalid'))
    info = extract_packet_info(packet)
    assert get_ip_addrs(packet) == ('2001:db8::10', '2001:db8::20')
    assert info['layers'] == ['Ethernet', 'IPv6', 'UDP', 'DNS']
    assert info['dns_qname'] == 'example.invalid'
    assert info['dns_qtype'] == 1
    assert guess_os(packet) is None


def test_nested_ip_keeps_existing_address_selection():
    packet = ethernet() / IP(src='192.0.2.10', dst='192.0.2.20') / IPv6(
        src='2001:db8::10', dst='2001:db8::20') / TCP()
    assert get_ip_addrs(packet) == ('192.0.2.10', '192.0.2.20')
    # 증거는 두 레이어를 기록하며 기존 IPv6 출력 우선순위를 보존한다.
    assert extract_packet_info(packet)['ip_src'] == '2001:db8::10'


def test_arp_and_non_ip_payload_are_not_invented_as_ip():
    packet = ethernet() / ARP(psrc='192.0.2.10', pdst='192.0.2.20')
    assert get_ip_addrs(packet) == (None, None)
    assert extract_packet_info(packet)['arp_psrc'] == '192.0.2.10'
    assert get_ip_addrs(Raw(b'opaque')) == (None, None)
    assert guess_os(packet) is None


def test_mutated_packet_has_fresh_addresses():
    packet = IP(src='192.0.2.10', dst='192.0.2.20')
    assert get_ip_addrs(packet)[0] == '192.0.2.10'
    packet.src = '192.0.2.30'
    assert get_ip_addrs(packet)[0] == '192.0.2.30'
