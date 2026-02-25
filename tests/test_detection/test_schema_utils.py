"""Tests for config_schema normalization utilities."""

import pytest

from netwatcher.detection.schema_utils import (
    normalize_schema,
    normalize_schema_field,
    schema_to_api,
)


class TestNormalizeSchemaField:
    """normalize_schema_field 함수 테스트."""

    # -- tuple format --

    def test_tuple_int(self):
        result = normalize_schema_field("threshold", (int, 15))
        assert result == {
            "type": int,
            "default": 15,
            "label": "threshold",
            "description": "",
            "min": None,
            "max": None,
        }

    def test_tuple_float(self):
        result = normalize_schema_field("z_score", (float, 3.0))
        assert result["type"] is float
        assert result["default"] == 3.0
        assert result["label"] == "z_score"

    def test_tuple_bool(self):
        result = normalize_schema_field("check_ja3", (bool, True))
        assert result["type"] is bool
        assert result["default"] is True

    def test_tuple_str(self):
        result = normalize_schema_field("rules_dir", (str, "config/rules"))
        assert result["type"] is str
        assert result["default"] == "config/rules"

    def test_tuple_list(self):
        result = normalize_schema_field("known_servers", (list, []))
        assert result["type"] is list
        assert result["default"] == []

    def test_tuple_list_with_values(self):
        ports = [22, 445, 3389]
        result = normalize_schema_field("lateral_ports", (list, ports))
        assert result["default"] == ports

    # -- dict format --

    def test_dict_full(self):
        spec = {
            "type": int,
            "default": 60,
            "label": "Window Seconds",
            "description": "Time window for analysis",
            "min": 1,
            "max": 3600,
        }
        result = normalize_schema_field("window_seconds", spec)
        assert result == spec

    def test_dict_minimal(self):
        """type과 default만 있는 최소한의 dict 형식."""
        spec = {"type": int, "default": 100}
        result = normalize_schema_field("threshold", spec)
        assert result["type"] is int
        assert result["default"] == 100
        assert result["label"] == "threshold"
        assert result["description"] == ""
        assert result["min"] is None
        assert result["max"] is None

    def test_dict_partial_with_label(self):
        spec = {"type": float, "default": 0.15, "label": "Beacon Tolerance"}
        result = normalize_schema_field("beacon_tolerance", spec)
        assert result["label"] == "Beacon Tolerance"
        assert result["description"] == ""
        assert result["min"] is None

    def test_dict_partial_with_description(self):
        spec = {
            "type": bool,
            "default": True,
            "description": "Enable JA3 fingerprint checking",
        }
        result = normalize_schema_field("check_ja3", spec)
        assert result["description"] == "Enable JA3 fingerprint checking"
        assert result["label"] == "check_ja3"

    def test_dict_with_min_max(self):
        spec = {"type": int, "default": 15, "min": 1, "max": 65535}
        result = normalize_schema_field("threshold", spec)
        assert result["min"] == 1
        assert result["max"] == 65535

    # -- invalid format --

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError, match="Invalid schema spec"):
            normalize_schema_field("bad", "not_a_valid_spec")

    def test_invalid_int_raises(self):
        with pytest.raises(ValueError, match="Invalid schema spec"):
            normalize_schema_field("bad", 42)

    def test_invalid_none_raises(self):
        with pytest.raises(ValueError, match="Invalid schema spec"):
            normalize_schema_field("bad", None)

    def test_invalid_tuple_length_one_raises(self):
        with pytest.raises(ValueError, match="Invalid tuple schema spec"):
            normalize_schema_field("bad", (int,))

    def test_invalid_tuple_length_three_raises(self):
        with pytest.raises(ValueError, match="Invalid tuple schema spec"):
            normalize_schema_field("bad", (int, 10, "extra"))

    def test_invalid_dict_missing_type_raises(self):
        with pytest.raises(ValueError, match="missing required key 'type'"):
            normalize_schema_field("bad", {"default": 10})

    def test_invalid_dict_missing_default_raises(self):
        with pytest.raises(ValueError, match="missing required key 'default'"):
            normalize_schema_field("bad", {"type": int})


class TestNormalizeSchema:
    """normalize_schema 함수 테스트."""

    def test_empty_schema(self):
        result = normalize_schema({})
        assert result == {}

    def test_all_tuple_format(self):
        schema = {
            "window_seconds": (int, 60),
            "threshold": (int, 15),
        }
        result = normalize_schema(schema)
        assert len(result) == 2
        assert result["window_seconds"]["type"] is int
        assert result["window_seconds"]["default"] == 60
        assert result["threshold"]["default"] == 15

    def test_all_dict_format(self):
        schema = {
            "check_ja3": {
                "type": bool,
                "default": True,
                "label": "JA3 Check",
                "description": "Enable JA3",
            },
        }
        result = normalize_schema(schema)
        assert result["check_ja3"]["label"] == "JA3 Check"
        assert result["check_ja3"]["description"] == "Enable JA3"

    def test_mixed_format(self):
        """tuple과 dict 형식이 혼합된 스키마."""
        schema = {
            "threshold": (int, 15),
            "z_score": {
                "type": float,
                "default": 3.0,
                "label": "Z-Score Threshold",
                "description": "Standard deviation multiplier",
                "min": 0.0,
                "max": 10.0,
            },
            "enabled": (bool, True),
        }
        result = normalize_schema(schema)
        assert len(result) == 3
        assert result["threshold"]["type"] is int
        assert result["z_score"]["label"] == "Z-Score Threshold"
        assert result["z_score"]["min"] == 0.0
        assert result["enabled"]["type"] is bool

    def test_preserves_key_order(self):
        schema = {
            "aaa": (int, 1),
            "bbb": (int, 2),
            "ccc": (int, 3),
        }
        result = normalize_schema(schema)
        assert list(result.keys()) == ["aaa", "bbb", "ccc"]


class TestSchemaToApi:
    """schema_to_api 함수 테스트."""

    def test_empty_schema(self):
        result = schema_to_api({})
        assert result == []

    def test_int_type_serialization(self):
        schema = {"threshold": (int, 15)}
        result = schema_to_api(schema)
        assert len(result) == 1
        field = result[0]
        assert field["key"] == "threshold"
        assert field["type"] == "int"
        assert field["default"] == 15
        assert field["label"] == "threshold"
        assert field["description"] == ""
        assert field["min"] is None
        assert field["max"] is None

    def test_float_type_serialization(self):
        schema = {"z_score": (float, 3.0)}
        result = schema_to_api(schema)
        assert result[0]["type"] == "float"

    def test_bool_type_serialization(self):
        schema = {"enabled": (bool, True)}
        result = schema_to_api(schema)
        assert result[0]["type"] == "bool"

    def test_str_type_serialization(self):
        schema = {"rules_dir": (str, "config/rules")}
        result = schema_to_api(schema)
        assert result[0]["type"] == "str"

    def test_list_type_serialization(self):
        schema = {"ports": (list, [22, 80])}
        result = schema_to_api(schema)
        assert result[0]["type"] == "list"
        assert result[0]["default"] == [22, 80]

    def test_full_dict_format(self):
        schema = {
            "threshold": {
                "type": int,
                "default": 15,
                "label": "Detection Threshold",
                "description": "Number of ports to trigger alert",
                "min": 1,
                "max": 65535,
            },
        }
        result = schema_to_api(schema)
        field = result[0]
        assert field["key"] == "threshold"
        assert field["type"] == "int"
        assert field["label"] == "Detection Threshold"
        assert field["description"] == "Number of ports to trigger alert"
        assert field["min"] == 1
        assert field["max"] == 65535

    def test_multiple_fields_order(self):
        """API 출력이 스키마 키 순서를 유지하는지 확인."""
        schema = {
            "window_seconds": (int, 60),
            "threshold": (int, 15),
            "cooldown": (int, 300),
        }
        result = schema_to_api(schema)
        assert len(result) == 3
        assert [f["key"] for f in result] == ["window_seconds", "threshold", "cooldown"]

    def test_mixed_format_api(self):
        schema = {
            "threshold": (int, 15),
            "tolerance": {
                "type": float,
                "default": 0.15,
                "label": "Tolerance",
                "description": "Beacon interval tolerance",
                "min": 0.0,
                "max": 1.0,
            },
        }
        result = schema_to_api(schema)
        assert len(result) == 2
        assert result[0]["type"] == "int"
        assert result[1]["type"] == "float"
        assert result[1]["label"] == "Tolerance"

    def test_unknown_type_uses_classname(self):
        """미지원 타입은 __name__을 문자열로 사용."""
        schema = {"data": (dict, {})}
        result = schema_to_api(schema)
        assert result[0]["type"] == "dict"

    def test_real_port_scan_schema(self):
        """실제 PortScanEngine의 config_schema와 동일한 형식 테스트."""
        schema = {
            "window_seconds": (int, 60),
            "threshold": (int, 15),
            "alerted_cooldown_seconds": (int, 300),
            "max_tracked_connections": (int, 10000),
        }
        result = schema_to_api(schema)
        assert len(result) == 4
        for field in result:
            assert field["type"] == "int"
            assert isinstance(field["default"], int)
            assert "key" in field

    def test_real_tls_fingerprint_schema(self):
        """실제 TlsFingerprintEngine과 유사한 혼합 타입 스키마 테스트."""
        schema = {
            "check_ja3": (bool, True),
            "tunnel_min_packets": (int, 30),
            "tunnel_cv_threshold": (float, 0.05),
        }
        result = schema_to_api(schema)
        types = [f["type"] for f in result]
        assert types == ["bool", "int", "float"]
