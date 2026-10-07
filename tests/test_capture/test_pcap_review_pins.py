"""Pinned evidence survives bounded retention and a writer restart."""
from pathlib import Path
import time
import pytest
from netwatcher.capture.pcap_writer import PCAPWriter


def snapshot():
    return ((time.time(), bytes.fromhex('0200000000200200000000100800') + bytes(80), 1),)


def test_review_pin_survives_restart_and_retention_skips_it(tmp_path):
    writer = PCAPWriter(str(tmp_path), max_files=2, max_deletes_per_second=10)
    first = writer.write_snapshot(1, snapshot())
    second = writer.write_snapshot(2, snapshot())
    state = writer.review_pin(1, actor='admin', reason='Reviewing incident', hours=1)
    assert state['pin_state'] == 'pinned'
    restarted = PCAPWriter(str(tmp_path), max_files=2, max_deletes_per_second=10)
    third = restarted.write_snapshot(3, snapshot())
    assert first and Path(first).exists()
    assert second and not Path(second).exists()
    assert third and Path(third).exists()
    assert restarted.evidence_availability(1)['pin']['confirmed_by'] == 'admin'


def test_all_pinned_storage_refuses_new_evidence_then_expiry_allows_retention(tmp_path):
    writer = PCAPWriter(str(tmp_path), max_files=1, max_deletes_per_second=10)
    first = writer.write_snapshot(1, snapshot())
    writer.review_pin(1, actor='admin', reason='Approval review', hours=1)
    assert writer.write_snapshot(2, snapshot()) is None
    assert Path(first).exists()
    writer._pins[Path(first).name]['expires_at'] = time.time() - 1
    assert writer.write_snapshot(2, snapshot())
    assert not Path(first).exists()
    assert writer.evidence_availability(1)['state'] == 'unavailable'


def test_corrupt_pin_manifest_fails_closed(tmp_path):
    writer = PCAPWriter(str(tmp_path), max_files=1)
    first = writer.write_snapshot(1, snapshot())
    (tmp_path / 'review-pins.json').write_text('{broken')
    restarted = PCAPWriter(str(tmp_path), max_files=1)
    assert restarted.write_snapshot(2, snapshot()) is None
    assert Path(first).exists()
    assert restarted.evidence_availability(1)['pin_state'] == 'unknown'


def test_unpin_is_explicit_and_ttl_is_bounded(tmp_path):
    writer = PCAPWriter(str(tmp_path))
    writer.write_snapshot(1, snapshot())
    with pytest.raises(ValueError, match='TTL'):
        writer.review_pin(1, actor='admin', reason='Review', hours=25)
    writer.review_pin(1, actor='admin', reason='Review', hours=1)
    state = writer.review_pin(1, actor='admin', reason='Review closed', enabled=False)
    assert state['pin_state'] == 'unpinned'
    with pytest.raises(FileNotFoundError):
        writer.review_pin(999, actor='admin', reason='Missing')
