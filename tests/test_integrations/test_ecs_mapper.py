"""ECS 매퍼 단위 테스트."""

from __future__ import annotations

from netwatcher.detection.models import Alert, Severity
from netwatcher.integrations.ecs_mapper import alert_to_ecs


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        engine="port_scan",
        severity=Severity.WARNING,
        title="Port Scan Detected",
        description="192.168.1.100 scanned 50 ports on 192.168.1.1",
        source_ip="192.168.1.100",
        dest_ip="192.168.1.1",
        confidence=0.85,
        mitre_attack_id="T1046",
        metadata={"unique_ports": 50},
    )
    defaults.update(overrides)
    return Alert(**defaults)


class TestAlertToEcs:
    def test_basic_fields(self):
        alert = _make_alert()
        doc   = alert_to_ecs(alert)

        assert doc["@timestamp"] == alert.timestamp
        assert doc["message"] == "Port Scan Detected"
        assert doc["event"]["kind"] == "alert"
        assert "intrusion_detection" in doc["event"]["category"]
        assert doc["event"]["severity"] == 3  # WARNING -> 3
        assert doc["event"]["reason"] == alert.description
        assert doc["rule"]["name"] == "port_scan"

    def test_source_destination(self):
        alert = _make_alert()
        doc   = alert_to_ecs(alert)

        assert doc["source"]["ip"] == "192.168.1.100"
        assert doc["destination"]["ip"] == "192.168.1.1"

    def test_source_mac_only(self):
        alert = _make_alert(source_ip=None, source_mac="aa:bb:cc:dd:ee:ff")
        doc   = alert_to_ecs(alert)

        assert doc["source"]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert "ip" not in doc["source"]

    def test_no_source_dest(self):
        alert = _make_alert(source_ip=None, dest_ip=None)
        doc   = alert_to_ecs(alert)

        assert "source" not in doc
        assert "destination" not in doc

    def test_mitre_attack_mapping(self):
        alert = _make_alert(mitre_attack_id="T1046")
        doc   = alert_to_ecs(alert)

        assert doc["threat"]["framework"] == "MITRE ATT&CK"
        techniques = doc["threat"]["technique"]
        assert len(techniques) == 1
        assert techniques[0]["id"] == "T1046"
        assert techniques[0]["name"] == "Network Service Discovery"
        assert "attack.mitre.org" in techniques[0]["reference"]

    def test_mitre_attack_unknown(self):
        alert = _make_alert(mitre_attack_id="T9999")
        doc   = alert_to_ecs(alert)

        assert doc["threat"]["technique"][0]["id"] == "T9999"
        assert "tactic" not in doc["threat"]

    def test_no_mitre_attack(self):
        alert = _make_alert(mitre_attack_id=None)
        doc   = alert_to_ecs(alert)

        assert "threat" not in doc

    def test_severity_critical(self):
        alert = _make_alert(severity=Severity.CRITICAL)
        doc   = alert_to_ecs(alert)

        assert doc["event"]["severity"] == 1

    def test_severity_info(self):
        alert = _make_alert(severity=Severity.INFO)
        doc   = alert_to_ecs(alert)

        assert doc["event"]["severity"] == 6

    def test_netwatcher_custom_fields(self):
        alert = _make_alert()
        doc   = alert_to_ecs(alert)

        assert doc["netwatcher"]["confidence"] == 0.85
        assert doc["netwatcher"]["metadata"]["unique_ports"] == 50

    def test_ecs_conversion_does_not_live_on_the_model(self):
        """도메인 모델은 출력 포맷을 알지 않는다.

        변환은 `integrations` 쪽에서만 한다 — 모델이 변환기를 가지면
        도메인과 출력 포맷이 서로를 부른다.
        """
        alert = _make_alert()
        assert not hasattr(alert, "to_ecs")
        assert alert_to_ecs(alert)["@timestamp"]
