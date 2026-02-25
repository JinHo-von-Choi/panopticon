"""Tests for the whitelist system."""

from netwatcher.detection.whitelist import Whitelist


class TestWhitelist:
    def test_ip_exact_match(self):
        wl = Whitelist({"ips": ["192.168.1.1", "10.0.0.1"]})
        assert wl.is_ip_whitelisted("192.168.1.1")
        assert wl.is_ip_whitelisted("10.0.0.1")
        assert not wl.is_ip_whitelisted("192.168.1.2")

    def test_ip_range_cidr(self):
        wl = Whitelist({"ip_ranges": ["192.168.1.0/24"]})
        assert wl.is_ip_whitelisted("192.168.1.1")
        assert wl.is_ip_whitelisted("192.168.1.254")
        assert not wl.is_ip_whitelisted("192.168.2.1")

    def test_mac_match(self):
        wl = Whitelist({"macs": ["AA:BB:CC:DD:EE:FF"]})
        assert wl.is_mac_whitelisted("aa:bb:cc:dd:ee:ff")
        assert not wl.is_mac_whitelisted("11:22:33:44:55:66")

    def test_domain_exact(self):
        wl = Whitelist({"domains": ["google.com"]})
        assert wl.is_domain_whitelisted("google.com")
        assert not wl.is_domain_whitelisted("evil.com")

    def test_domain_suffix(self):
        wl = Whitelist({"domain_suffixes": [".local", ".internal"]})
        assert wl.is_domain_whitelisted("host.local")
        assert wl.is_domain_whitelisted("app.internal")
        assert not wl.is_domain_whitelisted("evil.com")

    def test_is_whitelisted_combined(self):
        wl = Whitelist({
            "ips": ["10.0.0.1"],
            "domains": ["safe.com"],
        })
        assert wl.is_whitelisted(source_ip="10.0.0.1")
        assert wl.is_whitelisted(domain="safe.com")
        assert not wl.is_whitelisted(source_ip="10.0.0.2")

    def test_empty_whitelist(self):
        wl = Whitelist()
        assert not wl.is_whitelisted(source_ip="10.0.0.1")

    def test_add_remove(self):
        wl = Whitelist()
        wl.add_ip("1.2.3.4")
        assert wl.is_ip_whitelisted("1.2.3.4")
        wl.remove_ip("1.2.3.4")
        assert not wl.is_ip_whitelisted("1.2.3.4")

    def test_to_dict(self):
        wl = Whitelist({"ips": ["1.2.3.4"], "domains": ["test.com"]})
        d = wl.to_dict()
        assert "1.2.3.4" in d["ips"]
        assert "test.com" in d["domains"]

    def test_none_values(self):
        wl = Whitelist({"ips": ["1.2.3.4"]})
        assert not wl.is_ip_whitelisted(None)
        assert not wl.is_mac_whitelisted(None)
        assert not wl.is_domain_whitelisted(None)
