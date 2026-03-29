"""PlaybookEngine 테스트."""

from __future__ import annotations

import pytest

from netwatcher.detection.models import Alert, Severity
from netwatcher.hunting.playbook_engine import PlaybookAction, PlaybookEngine


@pytest.fixture
def playbooks_dir(tmp_path):
    """테스트용 플레이북 디렉토리를 생성한다."""
    pb_dir = tmp_path / "playbooks"
    pb_dir.mkdir()

    # Critical alert playbook
    (pb_dir / "critical_alert.yaml").write_text("""
id: "PB-001"
name: "Critical Alert Response"
trigger:
  severity: "CRITICAL"
  engines: ["threat_intel", "c2_beaconing"]
actions:
  - type: "enrich"
    params:
      lookup: ["whois", "dns_reverse"]
  - type: "notify"
    params:
      channel: "telegram"
      priority: "high"
""")

    # Warning playbook (severity only)
    (pb_dir / "warning_alert.yaml").write_text("""
id: "PB-002"
name: "Warning Alert Log"
trigger:
  severity: "WARNING"
actions:
  - type: "document"
    params:
      template: "warning_log"
""")

    return pb_dir


class TestPlaybookEngine:
    def test_load_playbooks(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))
        count = engine.load_playbooks()
        assert count == 2

    def test_load_empty_directory(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        engine = PlaybookEngine(playbooks_dir=str(empty_dir))
        count = engine.load_playbooks()
        assert count == 0

    def test_load_nonexistent_directory(self, tmp_path):
        engine = PlaybookEngine(playbooks_dir=str(tmp_path / "nonexistent"))
        count = engine.load_playbooks()
        assert count == 0

    def test_load_invalid_yaml(self, tmp_path):
        pb_dir = tmp_path / "playbooks"
        pb_dir.mkdir()
        (pb_dir / "bad.yaml").write_text("not: [valid: yaml: {{}")
        engine = PlaybookEngine(playbooks_dir=str(pb_dir))
        count = engine.load_playbooks()
        assert count == 0


@pytest.mark.asyncio
class TestPlaybookEvaluation:
    async def test_matches_critical_threat_intel(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))
        engine.load_playbooks()

        alert = Alert(
            engine="threat_intel",
            severity=Severity.CRITICAL,
            title="Known malicious IP",
            source_ip="10.0.0.5",
        )

        actions = await engine.evaluate(alert)
        assert len(actions) == 2
        assert actions[0].action_type == "enrich"
        assert actions[1].action_type == "notify"
        assert all(a.playbook_id == "PB-001" for a in actions)

    async def test_no_match_wrong_engine(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))
        engine.load_playbooks()

        alert = Alert(
            engine="port_scan",
            severity=Severity.CRITICAL,
            title="Port scan",
        )

        actions = await engine.evaluate(alert)
        # CRITICAL severity matches PB-001 trigger, but engine is not in ["threat_intel", "c2_beaconing"]
        assert len(actions) == 0

    async def test_matches_warning_severity(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))
        engine.load_playbooks()

        alert = Alert(
            engine="port_scan",
            severity=Severity.WARNING,
            title="Port scan detected",
        )

        actions = await engine.evaluate(alert)
        assert len(actions) == 1
        assert actions[0].playbook_id == "PB-002"
        assert actions[0].action_type == "document"

    async def test_no_match_info_severity(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))
        engine.load_playbooks()

        alert = Alert(
            engine="port_scan",
            severity=Severity.INFO,
            title="Minor scan",
        )

        actions = await engine.evaluate(alert)
        assert len(actions) == 0


@pytest.mark.asyncio
class TestPlaybookExecution:
    async def test_execute_enrich(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))

        actions = [
            PlaybookAction(
                playbook_id="PB-001",
                action_type="enrich",
                params={"lookup": ["whois"]},
            ),
        ]

        results = await engine.execute(actions)
        assert len(results) == 1
        assert results[0]["status"] == "completed"
        assert results[0]["action_type"] == "enrich"
        assert "whois" in results[0]["result"]

    async def test_execute_notify(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))

        actions = [
            PlaybookAction(
                playbook_id="PB-001",
                action_type="notify",
                params={"channel": "telegram", "priority": "high"},
            ),
        ]

        results = await engine.execute(actions)
        assert results[0]["result"]["channel"] == "telegram"

    async def test_execute_unknown_action(self, playbooks_dir):
        engine = PlaybookEngine(playbooks_dir=str(playbooks_dir))

        actions = [
            PlaybookAction(
                playbook_id="PB-001",
                action_type="quarantine",
                params={},
            ),
        ]

        results = await engine.execute(actions)
        assert results[0]["status"] == "skipped"


class TestPlaybookAction:
    def test_to_dict(self):
        action = PlaybookAction(
            playbook_id="PB-001",
            action_type="enrich",
            params={"lookup": ["whois"]},
        )
        d = action.to_dict()
        assert d["playbook_id"] == "PB-001"
        assert d["action_type"] == "enrich"
