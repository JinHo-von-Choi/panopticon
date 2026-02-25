"""Tests for DetectionEngine.validate_config() — type and range validation."""

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert
from scapy.all import Packet


class _DummyEngine(DetectionEngine):
    """Concrete engine for testing validate_config."""

    name = "test_engine"
    config_schema = {
        "threshold": {
            "type": int, "default": 15, "min": 1, "max": 100,
        },
        "tolerance": {
            "type": float, "default": 0.15, "min": 0.01, "max": 1.0,
        },
        "enabled_flag": (bool, True),
        "label": (str, "default"),
        "window": {
            "type": int, "default": 60, "min": 10, "max": 3600,
        },
    }

    def analyze(self, packet: Packet) -> Alert | None:
        return None


class TestValidateConfigType:
    def test_valid_config_no_warnings(self):
        engine = _DummyEngine({"threshold": 15, "tolerance": 0.15, "window": 60})
        assert engine.validate_config() == []

    def test_default_values_no_warnings(self):
        engine = _DummyEngine({})
        assert engine.validate_config() == []

    def test_wrong_type_int_for_str(self):
        engine = _DummyEngine({"label": 123})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "expected str" in warnings[0]

    def test_int_accepted_for_float(self):
        engine = _DummyEngine({"tolerance": 1})
        warnings = engine.validate_config()
        assert len(warnings) == 0

    def test_string_for_int(self):
        engine = _DummyEngine({"threshold": "abc"})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "expected int" in warnings[0]


class TestValidateConfigRange:
    def test_value_below_min(self):
        engine = _DummyEngine({"threshold": 0})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "below minimum" in warnings[0]
        assert "1" in warnings[0]

    def test_value_above_max(self):
        engine = _DummyEngine({"threshold": 200})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "above maximum" in warnings[0]
        assert "100" in warnings[0]

    def test_value_at_min_boundary(self):
        engine = _DummyEngine({"threshold": 1})
        warnings = engine.validate_config()
        assert len(warnings) == 0

    def test_value_at_max_boundary(self):
        engine = _DummyEngine({"threshold": 100})
        warnings = engine.validate_config()
        assert len(warnings) == 0

    def test_float_below_min(self):
        engine = _DummyEngine({"tolerance": 0.001})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "below minimum" in warnings[0]

    def test_float_above_max(self):
        engine = _DummyEngine({"tolerance": 2.0})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "above maximum" in warnings[0]

    def test_negative_value_below_min(self):
        engine = _DummyEngine({"threshold": -5})
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "below minimum" in warnings[0]

    def test_multiple_violations(self):
        engine = _DummyEngine({"threshold": 0, "tolerance": 5.0, "window": 5})
        warnings = engine.validate_config()
        assert len(warnings) == 3

    def test_tuple_schema_no_range_check(self):
        """Tuple-format schemas have no min/max, so only type is checked."""
        engine = _DummyEngine({"enabled_flag": True})
        warnings = engine.validate_config()
        assert len(warnings) == 0

    def test_bool_not_range_checked(self):
        """Bool values should not be range-checked even if schema has min/max."""
        engine = _DummyEngine({"enabled_flag": False})
        warnings = engine.validate_config()
        assert len(warnings) == 0

    def test_int_as_float_range_checked(self):
        """Int value passed for float field should still be range-checked."""
        engine = _DummyEngine({"tolerance": 5})  # int 5 > max 1.0
        warnings = engine.validate_config()
        assert len(warnings) == 1
        assert "above maximum" in warnings[0]
