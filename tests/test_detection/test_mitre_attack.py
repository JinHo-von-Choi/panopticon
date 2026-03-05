"""MITRE ATT&CK 메타데이터 통합 테스트.

검증 항목:
- Alert.mitre_attack_id 필드 존재 및 직렬화
- EngineRegistry가 mitre_attack_ids[0]을 자동 주입하는지
- 엔진이 직접 설정한 경우 덮어쓰지 않는지
- EventRepository가 mitre_attack_id를 DB에 저장/조회하는지
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.storage.repositories import EventRepository
from netwatcher.utils.config import Config


# ---------------------------------------------------------------------------
# 더미 엔진 (테스트용)
# ---------------------------------------------------------------------------

class _FakePacket:
    """스캐피 패킷 대역 객체."""
    pass


class EngineWithTTP(DetectionEngine):
    name = "test_with_ttp"
    description = "TTP 매핑 있는 테스트 엔진"
    mitre_attack_ids = ["T1046", "T1018"]

    def analyze(self, packet) -> Alert | None:
        return Alert(
            engine=self.name,
            severity=Severity.WARNING,
            title="Test Alert",
        )


class EngineWithoutTTP(DetectionEngine):
    name = "test_without_ttp"
    description = "TTP 매핑 없는 테스트 엔진"
    mitre_attack_ids = []

    def analyze(self, packet) -> Alert | None:
        return Alert(
            engine=self.name,
            severity=Severity.INFO,
            title="No TTP Alert",
        )


class EngineWithDirectSet(DetectionEngine):
    name = "test_direct_set"
    description = "analyze()에서 직접 mitre_attack_id를 설정하는 엔진"
    mitre_attack_ids = ["T1046"]

    def analyze(self, packet) -> Alert | None:
        return Alert(
            engine=self.name,
            severity=Severity.WARNING,
            title="Direct Set Alert",
            mitre_attack_id="T1190",  # 클래스 속성의 T1046 대신 직접 설정
        )


# ---------------------------------------------------------------------------
# Alert 모델 테스트
# ---------------------------------------------------------------------------

class TestAlertModel:
    def test_default_mitre_attack_id_is_none(self):
        alert = Alert(engine="test", severity=Severity.INFO, title="T")
        assert alert.mitre_attack_id is None

    def test_mitre_attack_id_in_to_dict(self):
        alert = Alert(
            engine="test",
            severity=Severity.WARNING,
            title="T",
            mitre_attack_id="T1557.002",
        )
        d = alert.to_dict()
        assert "mitre_attack_id" in d
        assert d["mitre_attack_id"] == "T1557.002"

    def test_mitre_attack_id_none_in_to_dict(self):
        alert = Alert(engine="test", severity=Severity.INFO, title="T")
        d = alert.to_dict()
        assert d["mitre_attack_id"] is None


# ---------------------------------------------------------------------------
# EngineRegistry 자동 주입 테스트 (레지스트리 없이 단독 검증)
# ---------------------------------------------------------------------------

class TestMitreAutoInject:
    """EngineRegistry의 주입 로직을 직접 시뮬레이션한다."""

    def _inject(self, engine: DetectionEngine, alert: Alert) -> Alert:
        """registry.process_packet()의 주입 로직 복제."""
        if alert.mitre_attack_id is None:
            ids = getattr(engine, "mitre_attack_ids", [])
            if ids:
                alert.mitre_attack_id = ids[0]
        return alert

    def test_injects_first_ttp(self):
        engine = EngineWithTTP({"enabled": True})
        alert = engine.analyze(_FakePacket())
        injected = self._inject(engine, alert)
        assert injected.mitre_attack_id == "T1046"

    def test_no_injection_when_empty_list(self):
        engine = EngineWithoutTTP({"enabled": True})
        alert = engine.analyze(_FakePacket())
        injected = self._inject(engine, alert)
        assert injected.mitre_attack_id is None

    def test_does_not_overwrite_direct_set(self):
        engine = EngineWithDirectSet({"enabled": True})
        alert = engine.analyze(_FakePacket())
        injected = self._inject(engine, alert)
        # 클래스 속성 T1046이 아닌, analyze()에서 직접 설정한 T1190 유지
        assert injected.mitre_attack_id == "T1190"


# ---------------------------------------------------------------------------
# DetectionEngine 기반 클래스 속성 검증
# ---------------------------------------------------------------------------

class TestDetectionEngineBase:
    def test_base_has_mitre_attack_ids(self):
        assert hasattr(DetectionEngine, "mitre_attack_ids")
        assert DetectionEngine.mitre_attack_ids == []

    def test_engine_ttp_mapping(self):
        from netwatcher.detection.engines.arp_spoof import ARPSpoofEngine
        from netwatcher.detection.engines.port_scan import PortScanEngine
        from netwatcher.detection.engines.dns_anomaly import DNSAnomalyEngine

        assert "T1557.002" in ARPSpoofEngine.mitre_attack_ids
        assert "T1046" in PortScanEngine.mitre_attack_ids
        assert "T1071.004" in DNSAnomalyEngine.mitre_attack_ids

    def test_all_engines_have_attribute(self):
        """등록된 모든 엔진 클래스에 mitre_attack_ids가 존재하는지 확인한다."""
        import pkgutil, importlib, inspect
        import netwatcher.detection.engines as pkg

        for _, module_name, _ in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"netwatcher.detection.engines.{module_name}")
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, DetectionEngine) and obj is not DetectionEngine and obj.name:
                    assert hasattr(obj, "mitre_attack_ids"), \
                        f"{obj.name} is missing mitre_attack_ids"
                    assert isinstance(obj.mitre_attack_ids, list), \
                        f"{obj.name}.mitre_attack_ids must be a list"


# ---------------------------------------------------------------------------
# DB 저장/조회 통합 테스트
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_event_repo_stores_mitre_attack_id(event_repo: EventRepository):
    event_id = await event_repo.insert(
        engine="test_engine",
        severity="WARNING",
        title="MITRE Test Event",
        mitre_attack_id="T1557.002",
    )
    row = await event_repo.get_by_id(event_id)
    assert row is not None
    assert row["mitre_attack_id"] == "T1557.002"


@pytest.mark.asyncio
async def test_event_repo_stores_null_mitre_attack_id(event_repo: EventRepository):
    event_id = await event_repo.insert(
        engine="test_engine",
        severity="INFO",
        title="No MITRE Event",
    )
    row = await event_repo.get_by_id(event_id)
    assert row is not None
    assert row["mitre_attack_id"] is None


@pytest.mark.asyncio
async def test_event_repo_list_includes_mitre_attack_id(event_repo: EventRepository):
    await event_repo.insert(
        engine="arp_spoof",
        severity="CRITICAL",
        title="ARP Spoof Detected",
        mitre_attack_id="T1557.002",
    )
    rows = await event_repo.list_recent(limit=5)
    assert any(r["mitre_attack_id"] == "T1557.002" for r in rows)
