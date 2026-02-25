"""Tests for BlocklistRepository and DeviceRepository extensions."""

import pytest


@pytest.mark.asyncio
async def test_blocklist_add_and_list(blocklist_repo):
    row_id = await blocklist_repo.add("ip", "10.0.0.1", "test note")
    assert row_id is not None

    items = await blocklist_repo.list_custom()
    assert len(items) == 1
    assert items[0]["value"] == "10.0.0.1"
    assert items[0]["entry_type"] == "ip"
    assert items[0]["notes"] == "test note"


@pytest.mark.asyncio
async def test_blocklist_add_duplicate(blocklist_repo):
    await blocklist_repo.add("ip", "10.0.0.1")
    row_id = await blocklist_repo.add("ip", "10.0.0.1")
    assert row_id is None  # duplicate

    count = await blocklist_repo.count_custom()
    assert count == 1


@pytest.mark.asyncio
async def test_blocklist_remove(blocklist_repo):
    await blocklist_repo.add("domain", "evil.com")
    deleted = await blocklist_repo.remove_by_value("domain", "evil.com")
    assert deleted is True

    deleted2 = await blocklist_repo.remove_by_value("domain", "evil.com")
    assert deleted2 is False


@pytest.mark.asyncio
async def test_blocklist_filter_by_type(blocklist_repo):
    await blocklist_repo.add("ip", "1.2.3.4")
    await blocklist_repo.add("domain", "bad.com")

    ips = await blocklist_repo.list_custom(entry_type="ip")
    assert len(ips) == 1
    assert ips[0]["value"] == "1.2.3.4"

    domains = await blocklist_repo.list_custom(entry_type="domain")
    assert len(domains) == 1
    assert domains[0]["value"] == "bad.com"


@pytest.mark.asyncio
async def test_blocklist_search(blocklist_repo):
    await blocklist_repo.add("ip", "192.168.1.1", "office router")
    await blocklist_repo.add("ip", "10.0.0.1", "lab server")

    results = await blocklist_repo.list_custom(search="office")
    assert len(results) == 1
    assert results[0]["value"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_blocklist_pagination(blocklist_repo):
    for i in range(10):
        await blocklist_repo.add("ip", f"10.0.0.{i}")

    page1 = await blocklist_repo.list_custom(limit=5, offset=0)
    assert len(page1) == 5

    page2 = await blocklist_repo.list_custom(limit=5, offset=5)
    assert len(page2) == 5

    total = await blocklist_repo.count_custom()
    assert total == 10


@pytest.mark.asyncio
async def test_get_all_custom_ips_and_domains(blocklist_repo):
    await blocklist_repo.add("ip", "1.1.1.1")
    await blocklist_repo.add("ip", "2.2.2.2")
    await blocklist_repo.add("domain", "evil.com")

    ips = await blocklist_repo.get_all_custom_ips()
    assert ips == {"1.1.1.1", "2.2.2.2"}

    domains = await blocklist_repo.get_all_custom_domains()
    assert domains == {"evil.com"}


@pytest.mark.asyncio
async def test_device_register(device_repo):
    device = await device_repo.register(
        mac_address="aa:bb:cc:dd:ee:01",
        nickname="Office PC",
        ip_address="192.168.1.10",
        hostname="office-pc.local",
        notes="Main workstation",
    )
    assert device is not None
    assert device["nickname"] == "Office PC"
    assert device["is_known"] == 1
    assert device["notes"] == "Main workstation"


@pytest.mark.asyncio
async def test_device_register_updates_existing(device_repo):
    # First create via upsert (simulating packet detection)
    await device_repo.upsert("aa:bb:cc:dd:ee:01", "192.168.1.10", vendor="Apple")

    # Then register with nickname
    device = await device_repo.register(
        mac_address="aa:bb:cc:dd:ee:01",
        nickname="MacBook Pro",
    )
    assert device["nickname"] == "MacBook Pro"
    assert device["is_known"] == 1
    assert device["vendor"] == "Apple"  # preserved from upsert
    assert device["ip_address"] == "192.168.1.10"  # preserved


@pytest.mark.asyncio
async def test_device_update(device_repo):
    await device_repo.register(
        mac_address="aa:bb:cc:dd:ee:01",
        nickname="Old Name",
    )

    device = await device_repo.update_device(
        mac_address="aa:bb:cc:dd:ee:01",
        nickname="New Name",
        notes="Updated notes",
    )
    assert device["nickname"] == "New Name"
    assert device["notes"] == "Updated notes"


@pytest.mark.asyncio
async def test_device_upsert_preserves_nickname(device_repo):
    """Verify that packet-triggered upsert does not overwrite nickname."""
    await device_repo.register(
        mac_address="aa:bb:cc:dd:ee:01",
        nickname="My Device",
        notes="important",
    )

    # Simulate packet detection updating the device
    await device_repo.upsert("aa:bb:cc:dd:ee:01", "192.168.1.20", packet_bytes=500)

    device = await device_repo.get_by_mac("aa:bb:cc:dd:ee:01")
    assert device["nickname"] == "My Device"  # preserved
    assert device["notes"] == "important"  # preserved
    assert device["total_packets"] == 1  # from upsert increment
