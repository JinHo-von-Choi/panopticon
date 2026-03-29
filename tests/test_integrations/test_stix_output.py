"""STIX 2.1 출력 채널 단위 테스트."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netwatcher.detection.models import Alert, Severity
from netwatcher.integrations.stix_output import (
    StixTaxiiChannel,
    alert_to_indicator,
    alert_to_sighting,
    build_stix_bundle,
    _NETWATCHER_IDENTITY_ID,
)


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        engine="threat_intel",
        severity=Severity.CRITICAL,
        title="Blocklist IP Matched",
        description="Connection to known malicious IP 203.0.113.50",
        source_ip="192.168.1.10",
        dest_ip="203.0.113.50",
        confidence=0.95,
        mitre_attack_id="T1071.001",
        metadata={"blocklist": "abuse.ch"},
    )
    defaults.update(overrides)
    return Alert(**defaults)


class TestAlertToIndicator:
    def test_basic_fields(self):
        alert     = _make_alert()
        indicator = alert_to_indicator(alert)

        assert indicator["type"] == "indicator"
        assert indicator["spec_version"] == "2.1"
        assert indicator["id"].startswith("indicator--")
        assert indicator["name"] == "Blocklist IP Matched"
        assert indicator["created_by_ref"] == _NETWATCHER_IDENTITY_ID

    def test_pattern_contains_ips(self):
        alert     = _make_alert()
        indicator = alert_to_indicator(alert)

        assert "192.168.1.10" in indicator["pattern"]
        assert "203.0.113.50" in indicator["pattern"]

    def test_pattern_no_ips(self):
        alert     = _make_alert(source_ip=None, dest_ip=None)
        indicator = alert_to_indicator(alert)

        assert "artifact:payload_bin" in indicator["pattern"]

    def test_confidence(self):
        alert     = _make_alert(confidence=0.75)
        indicator = alert_to_indicator(alert)

        assert indicator["confidence"] == 75

    def test_indicator_type_critical(self):
        indicator = alert_to_indicator(_make_alert(severity=Severity.CRITICAL))
        assert "malicious-activity" in indicator["indicator_types"]

    def test_indicator_type_warning(self):
        indicator = alert_to_indicator(_make_alert(severity=Severity.WARNING))
        assert "anomalous-activity" in indicator["indicator_types"]

    def test_indicator_type_info(self):
        indicator = alert_to_indicator(_make_alert(severity=Severity.INFO))
        assert "benign" in indicator["indicator_types"]

    def test_mitre_kill_chain(self):
        alert     = _make_alert(mitre_attack_id="T1071.001")
        indicator = alert_to_indicator(alert)

        phases = indicator.get("kill_chain_phases", [])
        assert len(phases) == 1
        assert phases[0]["kill_chain_name"] == "mitre-attack"

    def test_mitre_external_references(self):
        alert     = _make_alert(mitre_attack_id="T1046")
        indicator = alert_to_indicator(alert)

        refs = indicator.get("external_references", [])
        assert len(refs) == 1
        assert refs[0]["source_name"] == "mitre-attack"
        assert refs[0]["external_id"] == "T1046"
        assert "attack.mitre.org" in refs[0]["url"]

    def test_no_mitre(self):
        alert     = _make_alert(mitre_attack_id=None)
        indicator = alert_to_indicator(alert)

        assert "kill_chain_phases" not in indicator
        assert "external_references" not in indicator


class TestAlertToSighting:
    def test_basic_fields(self):
        alert    = _make_alert()
        sighting = alert_to_sighting(alert, "indicator--test-id")

        assert sighting["type"] == "sighting"
        assert sighting["spec_version"] == "2.1"
        assert sighting["sighting_of_ref"] == "indicator--test-id"
        assert sighting["count"] == 1

    def test_observed_data_refs(self):
        alert    = _make_alert()
        sighting = alert_to_sighting(alert, "indicator--test-id")

        refs = sighting.get("observed_data_refs", [])
        assert len(refs) == 2  # source + dest IP


class TestBuildStixBundle:
    def test_bundle_structure(self):
        alert  = _make_alert()
        bundle = build_stix_bundle(alert)

        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")

        obj_types = [o["type"] for o in bundle["objects"]]
        assert "identity" in obj_types
        assert "indicator" in obj_types
        assert "sighting" in obj_types

    def test_bundle_with_mitre(self):
        alert  = _make_alert(mitre_attack_id="T1046")
        bundle = build_stix_bundle(alert)

        obj_types = [o["type"] for o in bundle["objects"]]
        assert "attack-pattern" in obj_types
        assert "relationship" in obj_types

    def test_bundle_without_mitre(self):
        alert  = _make_alert(mitre_attack_id=None)
        bundle = build_stix_bundle(alert)

        obj_types = [o["type"] for o in bundle["objects"]]
        assert "attack-pattern" not in obj_types
        assert "relationship" not in obj_types

    def test_deterministic_indicator_id(self):
        """동일한 Alert는 동일한 indicator ID를 생성한다."""
        alert = _make_alert()
        b1    = build_stix_bundle(alert)
        b2    = build_stix_bundle(alert)

        ind1 = [o for o in b1["objects"] if o["type"] == "indicator"][0]
        ind2 = [o for o in b2["objects"] if o["type"] == "indicator"][0]
        assert ind1["id"] == ind2["id"]


class TestStixTaxiiChannel:
    def test_init(self):
        config = {
            "enabled": True,
            "taxii_url": "https://taxii.example.com",
            "collection_id": "col-123",
            "api_key": "secret",
            "min_severity": "WARNING",
        }
        ch = StixTaxiiChannel(config)
        assert ch.name == "stix_taxii"
        assert ch._taxii_url == "https://taxii.example.com"
        assert ch._collection_id == "col-123"

    @pytest.mark.asyncio
    async def test_send_without_taxii(self):
        """TAXII 미설정 시 번들 생성만 수행하고 True 반환."""
        config = {"enabled": True, "taxii_url": "", "collection_id": "", "min_severity": "INFO"}
        ch     = StixTaxiiChannel(config)
        alert  = _make_alert()

        result = await ch.send(alert)
        assert result is True

    @pytest.mark.asyncio
    async def test_send_to_taxii_success(self):
        config = {
            "enabled": True,
            "taxii_url": "https://taxii.example.com",
            "collection_id": "col-123",
            "api_key": "key",
            "min_severity": "INFO",
        }
        ch    = StixTaxiiChannel(config)
        alert = _make_alert()

        mock_resp = AsyncMock()
        mock_resp.status = 202

        mock_post_ctx = AsyncMock()
        mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_post_ctx.__aexit__  = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=mock_post_ctx)

        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_factory.__aexit__  = AsyncMock(return_value=False)

        with patch("netwatcher.integrations.stix_output.aiohttp.ClientSession", return_value=mock_session_factory):
            result = await ch.send(alert)

        assert result is True
        mock_session.post.assert_called_once()
        call_kwargs = mock_session.post.call_args
        assert "taxii.example.com" in call_kwargs.args[0]

    @pytest.mark.asyncio
    async def test_send_to_taxii_failure(self):
        config = {
            "enabled": True,
            "taxii_url": "https://taxii.example.com",
            "collection_id": "col-123",
            "api_key": "",
            "min_severity": "INFO",
        }
        ch    = StixTaxiiChannel(config)
        alert = _make_alert()

        mock_resp = AsyncMock()
        mock_resp.status = 403
        mock_resp.text   = AsyncMock(return_value="Forbidden")

        mock_post_ctx = AsyncMock()
        mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_post_ctx.__aexit__  = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=mock_post_ctx)

        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_factory.__aexit__  = AsyncMock(return_value=False)

        with patch("netwatcher.integrations.stix_output.aiohttp.ClientSession", return_value=mock_session_factory):
            result = await ch.send(alert)

        assert result is False
