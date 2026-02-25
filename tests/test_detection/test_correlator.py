"""Tests for alert correlation engine."""

from netwatcher.detection.correlator import AlertCorrelator
from netwatcher.detection.models import Alert, Severity


def make_alert(engine: str, source_ip: str, severity: Severity = Severity.WARNING) -> Alert:
    return Alert(
        engine=engine,
        severity=severity,
        title=f"Test alert from {engine}",
        description="Test description",
        source_ip=source_ip,
    )


class TestAlertCorrelator:
    def setup_method(self):
        self.correlator = AlertCorrelator(
            time_window=300,
            burst_threshold=3,
            burst_window=60,
        )

    def test_single_alert_no_incident(self):
        alert = make_alert("port_scan", "10.0.0.1")
        incident = self.correlator.process_alert(alert, event_id=1)
        assert incident is None

    def test_multi_engine_creates_incident(self):
        """Two different engines for same source should create incident."""
        a1 = make_alert("port_scan", "10.0.0.1")
        a2 = make_alert("lateral_movement", "10.0.0.1")

        self.correlator.process_alert(a1, event_id=1)
        incident = self.correlator.process_alert(a2, event_id=2)

        assert incident is not None
        assert "10.0.0.1" in incident.source_ips
        assert len(incident.engines) >= 2

    def test_burst_creates_incident(self):
        """Many alerts from same source should create burst incident."""
        for i in range(5):
            alert = make_alert("port_scan", "10.0.0.1")
            result = self.correlator.process_alert(alert, event_id=i + 1)

        # At some point we should get a burst or multi-alert incident
        incidents = self.correlator.get_incidents()
        assert len(incidents) >= 1

    def test_different_sources_independent(self):
        a1 = make_alert("port_scan", "10.0.0.1")
        a2 = make_alert("port_scan", "10.0.0.2")

        r1 = self.correlator.process_alert(a1, event_id=1)
        r2 = self.correlator.process_alert(a2, event_id=2)

        assert r1 is None
        assert r2 is None

    def test_resolve_incident(self):
        a1 = make_alert("port_scan", "10.0.0.1")
        a2 = make_alert("lateral_movement", "10.0.0.1")
        self.correlator.process_alert(a1, event_id=1)
        incident = self.correlator.process_alert(a2, event_id=2)

        assert incident is not None
        assert self.correlator.resolve_incident(incident.id)

        unresolved = self.correlator.get_incidents(include_resolved=False)
        resolved = self.correlator.get_incidents(include_resolved=True)
        assert len(unresolved) == 0
        assert len(resolved) >= 1

    def test_get_incident_by_id(self):
        a1 = make_alert("port_scan", "10.0.0.1")
        a2 = make_alert("lateral_movement", "10.0.0.1")
        self.correlator.process_alert(a1, event_id=1)
        incident = self.correlator.process_alert(a2, event_id=2)

        result = self.correlator.get_incident(incident.id)
        assert result is not None
        assert result["id"] == incident.id

    def test_kill_chain_detection(self):
        """Alerts progressing through kill chain should be detected."""
        # reconnaissance -> lateral_movement
        a1 = make_alert("port_scan", "10.0.0.1")  # reconnaissance
        a2 = make_alert("lateral_movement", "10.0.0.1")  # lateral_movement

        self.correlator.process_alert(a1, event_id=1)
        incident = self.correlator.process_alert(a2, event_id=2)

        assert incident is not None
        assert len(incident.kill_chain_stages) >= 2


class TestRansomwareLateralKillChain:
    def test_ransomware_lateral_mapped_to_lateral_movement_stage(self):
        """ransomware_lateral 엔진은 킬체인 lateral_movement 단계로 매핑되어야 한다."""
        from netwatcher.detection.correlator import _KILL_CHAIN_STAGES
        assert _KILL_CHAIN_STAGES.get("ransomware_lateral") == "lateral_movement"

    def test_port_scan_then_ransomware_lateral_creates_kill_chain_incident(self):
        """port_scan(recon) → ransomware_lateral(lateral) 시퀀스가 킬체인 인시던트를 생성한다."""
        corr = AlertCorrelator(time_window=300)
        corr.process_alert(make_alert("port_scan", "192.168.1.10"),          event_id=1)
        incident = corr.process_alert(make_alert("ransomware_lateral", "192.168.1.10"), event_id=2)
        assert incident is not None
        assert "kill_chain" in incident.rule or "multi_engine" in incident.rule
