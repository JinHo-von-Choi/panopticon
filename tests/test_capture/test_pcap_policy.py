from pathlib import Path

from scapy.all import IP, Ether, ARP, TCP, Raw, rdpcap

from netwatcher.capture.pcap_writer import PCAPWriter


def test_snapshots_are_immutable_and_single_asset_cannot_evict_other_evidence(tmp_path):
    writer = PCAPWriter(str(tmp_path), buffer_size=8, max_buffer_bytes=4096)
    other = IP(src="192.0.2.2", dst="192.0.2.3") / TCP()
    writer.add_packet(other)
    for _ in range(100):
        writer.add_packet(IP(src="192.0.2.1", dst="192.0.2.3") / TCP() / Raw(b"x" * 100))
    assert len(writer.snapshot("192.0.2.2", None)) == 1
    snapshot = writer.snapshot("192.0.2.1", None)
    assert len(snapshot) == 2
    assert writer._buffer_bytes <= 4096
    original = bytes(other)
    other[IP].src = "198.51.100.1"
    assert writer.snapshot("192.0.2.2", None)[0][1] == original
    path = writer.write_snapshot(1, snapshot)
    assert len(rdpcap(path)) == 2


def test_arp_evidence_and_retention_inventory_are_incremental(tmp_path, monkeypatch):
    writer = PCAPWriter(str(tmp_path), max_storage_mb=1, max_deletes_per_second=1)
    writer.add_packet(Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2"))
    def forbidden_scan(*args):
        raise AssertionError("per-alert directory scan")
    monkeypatch.setattr(Path, "glob", forbidden_scan)
    paths = [writer.capture_for_alert(i, "192.0.2.1", None) for i in range(3)]
    assert all(paths)
    assert len(rdpcap(paths[0])) == 1
    writer._max_storage_bytes = 0
    writer._enforce_storage_limit()
    assert sum(Path(path).exists() for path in paths) == 2
    writer._enforce_storage_limit()
    assert sum(Path(path).exists() for path in paths) == 2
