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


class TestKillChainScoring:
    def setup_method(self):
        self.correlator = AlertCorrelator(time_window=300)

    def test_compute_kc_score_empty(self):
        """KC 상태가 없으면 점수는 0이어야 한다."""
        assert self.correlator.compute_kc_score("10.0.0.99") == 0.0

    def test_update_kc_state_tracks_phase(self):
        """_update_kc_state가 호스트별 단계 상태를 기록한다."""
        now = 1000.0
        self.correlator._update_kc_state("10.0.0.1", "discovery", "WARNING", now)
        state = self.correlator._kc_state["10.0.0.1"]
        assert "discovery" in state
        count, sev, ts = state["discovery"]
        assert count == 1
        assert sev == "WARNING"
        assert ts == now

    def test_kc_state_increments_count(self):
        """동일 단계 반복 시 count가 증가한다."""
        self.correlator._update_kc_state("10.0.0.1", "discovery", "WARNING", 1000.0)
        self.correlator._update_kc_state("10.0.0.1", "discovery", "WARNING", 1001.0)
        count, _, _ = self.correlator._kc_state["10.0.0.1"]["discovery"]
        assert count == 2

    def test_kc_state_upgrades_severity(self):
        """동일 단계에서 더 높은 심각도가 반영된다."""
        self.correlator._update_kc_state("10.0.0.1", "exfiltration", "WARNING", 1000.0)
        self.correlator._update_kc_state("10.0.0.1", "exfiltration", "CRITICAL", 1001.0)
        _, sev, _ = self.correlator._kc_state["10.0.0.1"]["exfiltration"]
        assert sev == "CRITICAL"

    def test_kc_score_increases_with_more_phases(self):
        """다양한 킬체인 단계가 활성화될수록 점수가 상승한다."""
        now = 1000.0
        self.correlator._update_kc_state("10.0.0.1", "discovery", "WARNING", now)
        score1 = self.correlator.compute_kc_score("10.0.0.1", now)

        self.correlator._update_kc_state("10.0.0.1", "lateral_movement", "WARNING", now)
        score2 = self.correlator.compute_kc_score("10.0.0.1", now)

        self.correlator._update_kc_state("10.0.0.1", "exfiltration", "CRITICAL", now)
        score3 = self.correlator.compute_kc_score("10.0.0.1", now)

        assert score1 < score2 < score3

    def test_kc_score_decays_over_time(self):
        """시간이 지남에 따라 점수가 감쇠한다."""
        self.correlator._update_kc_state("10.0.0.1", "exfiltration", "CRITICAL", 1000.0)
        score_fresh = self.correlator.compute_kc_score("10.0.0.1", 1000.0)
        score_old = self.correlator.compute_kc_score("10.0.0.1", 1000.0 + 7200.0)
        assert score_old < score_fresh

    def test_kc_score_capped_at_one(self):
        """점수는 1.0을 초과하지 않는다."""
        now = 1000.0
        for phase in ["discovery", "lateral_movement", "exfiltration",
                       "command_and_control", "impact", "credential_access"]:
            self.correlator._update_kc_state("10.0.0.1", phase, "CRITICAL", now)
        score = self.correlator.compute_kc_score("10.0.0.1", now)
        assert score <= 1.0

    def test_kc_score_triggers_incident_via_process_alert(self):
        """높은 KC 점수가 kill_chain_score 규칙으로 인시던트를 생성한다."""
        corr = AlertCorrelator(time_window=300)
        corr._kc_score_threshold = 0.05
        phases = [
            ("port_scan", "discovery"),
            ("lateral_movement", "lateral_movement"),
            ("data_exfil", "exfiltration"),
        ]
        incident = None
        for i, (engine, _) in enumerate(phases):
            a = make_alert(engine, "10.0.0.1", severity=Severity.CRITICAL)
            incident = corr.process_alert(a, event_id=i + 1)
        assert incident is not None

    def test_unknown_phase_ignored(self):
        """알 수 없는 단계는 KC 상태에 추가되지 않는다."""
        self.correlator._update_kc_state("10.0.0.1", "unknown", "WARNING", 1000.0)
        assert "unknown" not in self.correlator._kc_state.get("10.0.0.1", {})


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
        # multi_engine 규칙이 먼저 평가되어 인시던트를 생성하고,
        # kill_chain 규칙은 동일 인시던트를 업데이트(rule 필드 유지)하므로
        # rule은 항상 "multi_engine"이다.
        assert incident.rule == "multi_engine"
        # kill_chain 단계는 update 경로에서 stages로 덮어쓰이므로 정확히 설정된다.
        assert incident.kill_chain_stages == ["discovery", "lateral_movement"]
