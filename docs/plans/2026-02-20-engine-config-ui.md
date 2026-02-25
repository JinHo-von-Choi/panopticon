# Engine Configuration UI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 대시보드에서 각 탐지 엔진의 설정을 실시간으로 조회/수정/토글할 수 있는 기능 구현.

**Architecture:** Schema-Driven Dynamic Form. 각 엔진의 `config_schema`를 API로 노출하여 프론트엔드가 자동으로 폼을 생성. 설정 변경 시 ruamel.yaml로 YAML 원본 보존하며 수정 + 엔진 즉시 핫리로드.

**Tech Stack:** FastAPI, ruamel.yaml, Vanilla JS (기존 패턴)

---

## Task 1: config_schema 하위 호환성 유틸리티

기존 tuple 형식 `(type, default)`과 새 dict 형식을 모두 정규화하는 헬퍼 함수 추가.

**Files:**
- Create: `netwatcher/detection/schema_utils.py`
- Test: `tests/test_detection/test_schema_utils.py`

**Step 1: 테스트 작성**

```python
# tests/test_detection/test_schema_utils.py
"""config_schema 정규화 유틸리티 테스트."""
import pytest
from netwatcher.detection.schema_utils import normalize_schema_field, normalize_schema, schema_to_api


class TestNormalizeSchemaField:
    def test_tuple_format(self):
        result = normalize_schema_field("window_seconds", (int, 60))
        assert result == {
            "type": int,
            "default": 60,
            "label": "window_seconds",
            "description": "",
            "min": None,
            "max": None,
        }

    def test_dict_format(self):
        result = normalize_schema_field("threshold", {
            "type": int, "default": 15,
            "label": "Scan Threshold",
            "description": "Ports to trigger alert",
            "min": 1, "max": 1000,
        })
        assert result["label"] == "Scan Threshold"
        assert result["min"] == 1
        assert result["max"] == 1000

    def test_dict_format_defaults(self):
        result = normalize_schema_field("enabled", {"type": bool, "default": True})
        assert result["label"] == "enabled"
        assert result["description"] == ""
        assert result["min"] is None

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError):
            normalize_schema_field("bad", "not_a_tuple_or_dict")


class TestNormalizeSchema:
    def test_mixed_formats(self):
        schema = {
            "threshold": (int, 15),
            "enabled": {"type": bool, "default": True, "label": "Enabled"},
        }
        result = normalize_schema(schema)
        assert "threshold" in result
        assert result["enabled"]["label"] == "Enabled"


class TestSchemaToApi:
    def test_serialization(self):
        schema = {"window": (int, 60)}
        result = schema_to_api(schema)
        assert result == [
            {
                "key": "window",
                "type": "int",
                "default": 60,
                "label": "window",
                "description": "",
                "min": None,
                "max": None,
            }
        ]

    def test_list_type(self):
        schema = {"ports": (list, [22, 80])}
        result = schema_to_api(schema)
        assert result[0]["type"] == "list"
        assert result[0]["default"] == [22, 80]

    def test_float_type(self):
        schema = {"multiplier": (float, 3.0)}
        result = schema_to_api(schema)
        assert result[0]["type"] == "float"

    def test_bool_type(self):
        schema = {"check": (bool, True)}
        result = schema_to_api(schema)
        assert result[0]["type"] == "bool"
```

**Step 2: 테스트 실행 (실패 확인)**

Run: `.venv/bin/python -m pytest tests/test_detection/test_schema_utils.py -v`
Expected: FAIL (모듈 없음)

**Step 3: 구현**

```python
# netwatcher/detection/schema_utils.py
"""config_schema 정규화 유틸리티.

기존 tuple 형식 (type, default)과 확장 dict 형식을 통일된 dict로 변환.
"""
from __future__ import annotations
from typing import Any

# Python type -> API 문자열 매핑
_TYPE_NAMES: dict[type, str] = {
    int: "int",
    float: "float",
    bool: "bool",
    str: "str",
    list: "list",
}


def normalize_schema_field(key: str, spec: tuple | dict) -> dict[str, Any]:
    """단일 스키마 필드를 정규화된 dict로 변환."""
    if isinstance(spec, tuple) and len(spec) == 2:
        expected_type, default = spec
        return {
            "type": expected_type,
            "default": default,
            "label": key,
            "description": "",
            "min": None,
            "max": None,
        }
    if isinstance(spec, dict):
        return {
            "type": spec["type"],
            "default": spec["default"],
            "label": spec.get("label", key),
            "description": spec.get("description", ""),
            "min": spec.get("min"),
            "max": spec.get("max"),
        }
    raise ValueError(f"Invalid schema format for key '{key}': {type(spec)}")


def normalize_schema(schema: dict[str, tuple | dict]) -> dict[str, dict[str, Any]]:
    """전체 config_schema를 정규화."""
    return {key: normalize_schema_field(key, spec) for key, spec in schema.items()}


def schema_to_api(schema: dict[str, tuple | dict]) -> list[dict[str, Any]]:
    """config_schema를 API 응답용 직렬화 리스트로 변환."""
    result = []
    for key, spec in schema.items():
        normalized = normalize_schema_field(key, spec)
        result.append({
            "key": key,
            "type": _TYPE_NAMES.get(normalized["type"], "str"),
            "default": normalized["default"],
            "label": normalized["label"],
            "description": normalized["description"],
            "min": normalized["min"],
            "max": normalized["max"],
        })
    return result
```

**Step 4: 테스트 통과 확인**

Run: `.venv/bin/python -m pytest tests/test_detection/test_schema_utils.py -v`
Expected: ALL PASS

**Step 5: 커밋**

```bash
git add netwatcher/detection/schema_utils.py tests/test_detection/test_schema_utils.py
git commit -m "feat(detection): config_schema 정규화 유틸리티 추가"
```

---

## Task 2: EngineRegistry 핫리로드 메서드

레지스트리에 엔진 조회/재생성/토글 메서드 추가.

**Files:**
- Modify: `netwatcher/detection/registry.py`
- Test: `tests/test_detection/test_registry_reload.py`

**Step 1: 테스트 작성**

```python
# tests/test_detection/test_registry_reload.py
"""EngineRegistry 핫리로드 기능 테스트."""
import pytest
from unittest.mock import MagicMock, patch

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert
from netwatcher.detection.registry import EngineRegistry
from netwatcher.utils.config import Config


class DummyEngine(DetectionEngine):
    name = "dummy"
    config_schema = {"threshold": (int, 10)}

    def __init__(self, config):
        super().__init__(config)
        self.threshold = config.get("threshold", 10)

    def analyze(self, packet):
        return None


class TestGetEngineInfo:
    def test_get_engine_info_found(self):
        config = Config({"engines": {"dummy": {"enabled": True, "threshold": 20}}})
        registry = EngineRegistry(config)
        engine = DummyEngine({"enabled": True, "threshold": 20})
        registry._engines.append(engine)
        registry._engine_classes = {"dummy": DummyEngine}

        info = registry.get_engine_info("dummy")
        assert info is not None
        assert info["name"] == "dummy"
        assert info["enabled"] is True
        assert info["config"]["threshold"] == 20

    def test_get_engine_info_not_found(self):
        config = Config({"engines": {}})
        registry = EngineRegistry(config)
        registry._engine_classes = {}
        assert registry.get_engine_info("nonexistent") is None


class TestGetAllEngineInfo:
    def test_returns_all(self):
        config = Config({"engines": {"dummy": {"enabled": True}}})
        registry = EngineRegistry(config)
        engine = DummyEngine({"enabled": True})
        registry._engines.append(engine)
        registry._engine_classes = {"dummy": DummyEngine}

        result = registry.get_all_engine_info()
        assert len(result) == 1
        assert result[0]["name"] == "dummy"


class TestReloadEngine:
    def test_reload_engine_success(self):
        config = Config({"engines": {"dummy": {"enabled": True, "threshold": 20}}})
        registry = EngineRegistry(config)
        engine = DummyEngine({"enabled": True, "threshold": 10})
        registry._engines.append(engine)
        registry._engine_classes = {"dummy": DummyEngine}
        registry._last_tick["dummy"] = 0.0

        new_config = {"enabled": True, "threshold": 99}
        ok, err = registry.reload_engine("dummy", new_config)
        assert ok is True
        assert err is None
        assert registry._engines[0].threshold == 99

    def test_reload_unknown_engine(self):
        config = Config({"engines": {}})
        registry = EngineRegistry(config)
        registry._engine_classes = {}
        ok, err = registry.reload_engine("unknown", {})
        assert ok is False
        assert "not found" in err.lower() or "Unknown" in err


class TestDisableEngine:
    def test_disable_engine(self):
        config = Config({"engines": {"dummy": {"enabled": True}}})
        registry = EngineRegistry(config)
        engine = DummyEngine({"enabled": True})
        registry._engines.append(engine)
        registry._engine_classes = {"dummy": DummyEngine}

        ok, err = registry.disable_engine("dummy")
        assert ok is True
        assert len(registry._engines) == 0

    def test_disable_already_disabled(self):
        config = Config({"engines": {}})
        registry = EngineRegistry(config)
        registry._engine_classes = {"dummy": DummyEngine}
        ok, err = registry.disable_engine("dummy")
        # Should succeed (idempotent)
        assert ok is True


class TestEnableEngine:
    def test_enable_engine(self):
        config = Config({"engines": {"dummy": {"enabled": True, "threshold": 42}}})
        registry = EngineRegistry(config)
        registry._engine_classes = {"dummy": DummyEngine}

        ok, err = registry.enable_engine("dummy", {"enabled": True, "threshold": 42})
        assert ok is True
        assert len(registry._engines) == 1
        assert registry._engines[0].threshold == 42
```

**Step 2: 테스트 실행 (실패 확인)**

Run: `.venv/bin/python -m pytest tests/test_detection/test_registry_reload.py -v`
Expected: FAIL (메서드 없음)

**Step 3: 구현**

`netwatcher/detection/registry.py`에 다음 메서드 추가:

1. `discover_and_register()`에서 `_engine_classes: dict[str, type[DetectionEngine]]`도 함께 저장 (엔진 이름 -> 클래스 매핑)
2. `get_engine_info(name)` → 엔진 이름으로 현재 상태/config/schema 조회
3. `get_all_engine_info()` → 전체 엔진 정보 리스트
4. `reload_engine(name, new_config)` → 기존 엔진 shutdown + 새 config로 재생성
5. `disable_engine(name)` → 엔진 shutdown + 리스트에서 제거
6. `enable_engine(name, config)` → 새 엔진 인스턴스 생성 + 등록

핵심 변경:
```python
# discover_and_register() 내부 - 클래스 등록 추가
self._engine_classes: dict[str, type[DetectionEngine]] = {}
# ... 기존 로직 ...
self._engine_classes[obj.name] = obj  # 각 엔진 발견 시

def get_engine_info(self, name: str) -> dict | None:
    """엔진 이름으로 현재 상태/config/schema 조회."""
    from netwatcher.detection.schema_utils import schema_to_api
    engine = next((e for e in self._engines if e.name == name), None)
    cls = self._engine_classes.get(name)
    if engine is None and cls is None:
        return None
    if engine is not None:
        return {
            "name": engine.name,
            "enabled": True,
            "config": dict(engine.config),
            "schema": schema_to_api(cls.config_schema if cls else engine.config_schema),
        }
    # disabled 엔진: YAML config에서 로드
    engine_config = self._config.get(f"engines.{name}", {})
    if not isinstance(engine_config, dict):
        engine_config = {}
    return {
        "name": name,
        "enabled": False,
        "config": engine_config,
        "schema": schema_to_api(cls.config_schema),
    }

def get_all_engine_info(self) -> list[dict]:
    """전체 엔진 정보 리스트 (활성 + 비활성)."""
    result = []
    seen = set()
    for engine in self._engines:
        seen.add(engine.name)
        result.append(self.get_engine_info(engine.name))
    for name in self._engine_classes:
        if name not in seen:
            result.append(self.get_engine_info(name))
    return [r for r in result if r is not None]

def reload_engine(self, name: str, new_config: dict) -> tuple[bool, str | None]:
    """엔진을 새 config로 재생성."""
    cls = self._engine_classes.get(name)
    if cls is None:
        return False, f"Unknown engine: {name}"
    # 기존 엔진 찾기 + shutdown
    old_idx = None
    for i, e in enumerate(self._engines):
        if e.name == name:
            old_idx = i
            e.shutdown()
            break
    try:
        new_engine = cls(new_config)
        warnings = new_engine.validate_config()
        if self._whitelist:
            new_engine.set_whitelist(self._whitelist)
        if old_idx is not None:
            self._engines[old_idx] = new_engine
        else:
            self._engines.append(new_engine)
        self._last_tick[name] = 0.0
        return True, None
    except Exception as exc:
        return False, str(exc)

def disable_engine(self, name: str) -> tuple[bool, str | None]:
    """엔진 비활성화: shutdown + 리스트에서 제거."""
    for i, e in enumerate(self._engines):
        if e.name == name:
            e.shutdown()
            self._engines.pop(i)
            self._last_tick.pop(name, None)
            return True, None
    return True, None  # idempotent

def enable_engine(self, name: str, config: dict) -> tuple[bool, str | None]:
    """비활성 엔진을 새 config로 활성화."""
    # 이미 활성화된 경우 reload로 위임
    if any(e.name == name for e in self._engines):
        return self.reload_engine(name, config)
    return self.reload_engine(name, config)
```

**Step 4: 테스트 통과 확인**

Run: `.venv/bin/python -m pytest tests/test_detection/test_registry_reload.py -v`
Expected: ALL PASS

**Step 5: 전체 테스트 회귀 확인**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: ALL PASS (기존 571 + 신규)

**Step 6: 커밋**

```bash
git add netwatcher/detection/registry.py tests/test_detection/test_registry_reload.py
git commit -m "feat(detection): EngineRegistry 핫리로드/토글 메서드 추가"
```

---

## Task 3: YAML 설정 수정 서비스

ruamel.yaml 기반으로 주석/구조를 보존하며 엔진 설정 섹션만 업데이트하는 서비스.

**Files:**
- Create: `netwatcher/utils/yaml_editor.py`
- Test: `tests/test_utils/test_yaml_editor.py`
- Modify: `requirements.txt` (ruamel.yaml 추가)

**Step 1: 의존성 추가**

```bash
echo "ruamel.yaml>=0.18.0" >> requirements.txt
.venv/bin/pip install "ruamel.yaml>=0.18.0"
```

**Step 2: 테스트 작성**

```python
# tests/test_utils/test_yaml_editor.py
"""YAML 설정 편집기 테스트."""
import pytest
from pathlib import Path
from netwatcher.utils.yaml_editor import YamlConfigEditor


SAMPLE_YAML = """\
# NetWatcher config
netwatcher:
  engines:
    port_scan:
      enabled: true
      window_seconds: 60    # sliding window
      threshold: 15
    dns_anomaly:
      enabled: true
      entropy_threshold: 3.8
"""


class TestYamlConfigEditor:
    def test_update_engine_config(self, tmp_path):
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(SAMPLE_YAML)

        editor = YamlConfigEditor(str(yaml_path))
        editor.update_engine_config("port_scan", {"threshold": 20, "window_seconds": 120})

        # Re-read and verify
        content = yaml_path.read_text()
        assert "threshold: 20" in content
        assert "window_seconds: 120" in content
        # Comments preserved
        assert "# sliding window" in content
        # Other engine untouched
        assert "entropy_threshold: 3.8" in content

    def test_update_creates_backup(self, tmp_path):
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(SAMPLE_YAML)

        editor = YamlConfigEditor(str(yaml_path))
        editor.update_engine_config("port_scan", {"threshold": 25})

        bak = tmp_path / "config.yaml.bak"
        assert bak.exists()
        # Backup contains original
        assert "threshold: 15" in bak.read_text()

    def test_toggle_enabled(self, tmp_path):
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(SAMPLE_YAML)

        editor = YamlConfigEditor(str(yaml_path))
        editor.update_engine_config("port_scan", {"enabled": False})

        content = yaml_path.read_text()
        assert "enabled: false" in content

    def test_get_engine_config(self, tmp_path):
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(SAMPLE_YAML)

        editor = YamlConfigEditor(str(yaml_path))
        config = editor.get_engine_config("port_scan")
        assert config["threshold"] == 15
        assert config["enabled"] is True

    def test_get_engine_config_not_found(self, tmp_path):
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(SAMPLE_YAML)

        editor = YamlConfigEditor(str(yaml_path))
        assert editor.get_engine_config("nonexistent") is None

    def test_top_level_comment_preserved(self, tmp_path):
        yaml_path = tmp_path / "config.yaml"
        yaml_path.write_text(SAMPLE_YAML)

        editor = YamlConfigEditor(str(yaml_path))
        editor.update_engine_config("port_scan", {"threshold": 30})

        content = yaml_path.read_text()
        assert "# NetWatcher config" in content
```

**Step 3: 테스트 실행 (실패 확인)**

Run: `.venv/bin/python -m pytest tests/test_utils/test_yaml_editor.py -v`

**Step 4: 구현**

```python
# netwatcher/utils/yaml_editor.py
"""YAML 설정 파일 편집기. ruamel.yaml로 주석/구조 보존."""
from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

logger = logging.getLogger(__name__)


class YamlConfigEditor:
    """config/default.yaml의 엔진 설정 섹션을 안전하게 수정."""

    def __init__(self, yaml_path: str) -> None:
        self._path = Path(yaml_path)
        self._yaml = YAML()
        self._yaml.preserve_quotes = True

    def _load(self) -> dict:
        with open(self._path, encoding="utf-8") as f:
            return self._yaml.load(f)

    def _save(self, data: dict) -> None:
        with open(self._path, "w", encoding="utf-8") as f:
            self._yaml.dump(data, f)

    def _backup(self) -> None:
        bak = self._path.with_suffix(self._path.suffix + ".bak")
        shutil.copy2(self._path, bak)

    def get_engine_config(self, engine_name: str) -> dict | None:
        """엔진의 현재 YAML 설정을 dict로 반환."""
        data = self._load()
        engines = data.get("netwatcher", {}).get("engines", {})
        section = engines.get(engine_name)
        if section is None:
            return None
        return dict(section)

    def update_engine_config(self, engine_name: str, updates: dict[str, Any]) -> None:
        """엔진 설정의 특정 키만 업데이트. 백업 후 저장."""
        self._backup()
        data = self._load()
        engines = data.get("netwatcher", {}).get("engines", {})
        if engine_name not in engines:
            engines[engine_name] = {}
        section = engines[engine_name]
        for key, value in updates.items():
            section[key] = value
        self._save(data)
        logger.info("Updated engine config: %s -> %s", engine_name, updates)
```

**Step 5: 테스트 통과 확인**

Run: `.venv/bin/python -m pytest tests/test_utils/test_yaml_editor.py -v`
Expected: ALL PASS

**Step 6: 커밋**

```bash
git add requirements.txt netwatcher/utils/yaml_editor.py tests/test_utils/test_yaml_editor.py
git commit -m "feat(utils): ruamel.yaml 기반 YAML 설정 편집기 추가"
```

---

## Task 4: Engines REST API 라우터

엔진 조회/수정/토글 API 엔드포인트 구현.

**Files:**
- Create: `netwatcher/web/routes/engines.py`
- Modify: `netwatcher/web/server.py` (라우터 등록)
- Test: `tests/test_web/test_engines_api.py`

**Step 1: 테스트 작성**

```python
# tests/test_web/test_engines_api.py
"""Engines API 테스트."""
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from netwatcher.web.routes.engines import create_engines_router


@pytest.fixture
def mock_registry():
    reg = MagicMock()
    reg.get_all_engine_info.return_value = [
        {
            "name": "port_scan",
            "enabled": True,
            "config": {"threshold": 15, "window_seconds": 60, "enabled": True},
            "schema": [
                {"key": "threshold", "type": "int", "default": 15, "label": "threshold", "description": "", "min": None, "max": None},
                {"key": "window_seconds", "type": "int", "default": 60, "label": "window_seconds", "description": "", "min": None, "max": None},
            ],
        }
    ]
    reg.get_engine_info.return_value = {
        "name": "port_scan",
        "enabled": True,
        "config": {"threshold": 15, "window_seconds": 60, "enabled": True},
        "schema": [
            {"key": "threshold", "type": "int", "default": 15, "label": "threshold", "description": "", "min": None, "max": None},
        ],
    }
    reg.reload_engine.return_value = (True, None)
    reg.disable_engine.return_value = (True, None)
    reg.enable_engine.return_value = (True, None)
    return reg


@pytest.fixture
def mock_yaml_editor():
    editor = MagicMock()
    editor.get_engine_config.return_value = {"threshold": 15, "enabled": True}
    return editor


@pytest.fixture
def client(mock_registry, mock_yaml_editor):
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(
        create_engines_router(mock_registry, mock_yaml_editor),
        prefix="/api",
    )
    return TestClient(app)


class TestListEngines:
    def test_list_all(self, client, mock_registry):
        resp = client.get("/api/engines")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["engines"]) == 1
        assert data["engines"][0]["name"] == "port_scan"


class TestGetEngine:
    def test_get_found(self, client):
        resp = client.get("/api/engines/port_scan")
        assert resp.status_code == 200
        assert resp.json()["engine"]["name"] == "port_scan"

    def test_get_not_found(self, client, mock_registry):
        mock_registry.get_engine_info.return_value = None
        resp = client.get("/api/engines/nonexistent")
        assert resp.status_code == 404


class TestUpdateConfig:
    def test_update_success(self, client, mock_registry, mock_yaml_editor):
        resp = client.put(
            "/api/engines/port_scan/config",
            json={"threshold": 20},
        )
        assert resp.status_code == 200
        mock_yaml_editor.update_engine_config.assert_called_once()
        mock_registry.reload_engine.assert_called_once()

    def test_update_engine_not_found(self, client, mock_registry):
        mock_registry.get_engine_info.return_value = None
        resp = client.put("/api/engines/bad/config", json={"x": 1})
        assert resp.status_code == 404


class TestToggleEngine:
    def test_disable(self, client, mock_registry, mock_yaml_editor):
        resp = client.patch(
            "/api/engines/port_scan/toggle",
            json={"enabled": False},
        )
        assert resp.status_code == 200
        mock_yaml_editor.update_engine_config.assert_called()
        mock_registry.disable_engine.assert_called_once_with("port_scan")

    def test_enable(self, client, mock_registry, mock_yaml_editor):
        mock_registry.get_engine_info.return_value = {
            "name": "port_scan", "enabled": False,
            "config": {"threshold": 15, "enabled": False},
            "schema": [],
        }
        resp = client.patch(
            "/api/engines/port_scan/toggle",
            json={"enabled": True},
        )
        assert resp.status_code == 200
        mock_registry.enable_engine.assert_called_once()
```

**Step 2: 테스트 실행 (실패 확인)**

Run: `.venv/bin/python -m pytest tests/test_web/test_engines_api.py -v`

**Step 3: 구현 - 라우터**

```python
# netwatcher/web/routes/engines.py
"""Engine configuration REST API."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from netwatcher.detection.registry import EngineRegistry
    from netwatcher.utils.yaml_editor import YamlConfigEditor

logger = logging.getLogger(__name__)


class ToggleRequest(BaseModel):
    enabled: bool


def create_engines_router(
    registry: EngineRegistry,
    yaml_editor: YamlConfigEditor,
) -> APIRouter:
    """Engine configuration API 라우터."""
    router = APIRouter(tags=["engines"])

    @router.get("/engines")
    async def list_engines():
        engines = registry.get_all_engine_info()
        return {"engines": engines}

    @router.get("/engines/{name}")
    async def get_engine(name: str):
        info = registry.get_engine_info(name)
        if info is None:
            return JSONResponse({"error": f"Engine not found: {name}"}, status_code=404)
        return {"engine": info}

    @router.put("/engines/{name}/config")
    async def update_engine_config(name: str, body: dict[str, Any]):
        info = registry.get_engine_info(name)
        if info is None:
            return JSONResponse({"error": f"Engine not found: {name}"}, status_code=404)

        # YAML 저장
        try:
            yaml_editor.update_engine_config(name, body)
        except Exception as exc:
            logger.exception("Failed to update YAML for engine %s", name)
            return JSONResponse({"error": f"YAML update failed: {exc}"}, status_code=500)

        # 엔진 핫리로드
        merged = dict(info["config"])
        merged.update(body)
        ok, err = registry.reload_engine(name, merged)
        if not ok:
            return JSONResponse({"error": f"Engine reload failed: {err}"}, status_code=500)

        return {"status": "ok", "engine": registry.get_engine_info(name)}

    @router.patch("/engines/{name}/toggle")
    async def toggle_engine(name: str, body: ToggleRequest):
        info = registry.get_engine_info(name)
        if info is None:
            return JSONResponse({"error": f"Engine not found: {name}"}, status_code=404)

        # YAML 저장
        try:
            yaml_editor.update_engine_config(name, {"enabled": body.enabled})
        except Exception as exc:
            return JSONResponse({"error": f"YAML update failed: {exc}"}, status_code=500)

        if body.enabled:
            # 엔진 활성화
            config = yaml_editor.get_engine_config(name) or {}
            config["enabled"] = True
            ok, err = registry.enable_engine(name, config)
        else:
            # 엔진 비활성화
            ok, err = registry.disable_engine(name)

        if not ok:
            return JSONResponse({"error": f"Toggle failed: {err}"}, status_code=500)

        return {"status": "ok", "name": name, "enabled": body.enabled}

    return router
```

**Step 4: server.py에 라우터 등록**

`netwatcher/web/server.py`의 `create_app()` 함수에 `registry` 파라미터 추가 및 engines 라우터 등록:

```python
# create_app 시그니처에 추가:
#   registry: EngineRegistry | None = None,
#   yaml_editor: YamlConfigEditor | None = None,

# 라우터 등록 (signature_engine 블록 아래):
if registry is not None and yaml_editor is not None:
    from netwatcher.web.routes.engines import create_engines_router
    app.include_router(
        create_engines_router(registry, yaml_editor),
        prefix="/api",
    )
```

그리고 `netwatcher/app.py`에서 `create_app()` 호출 시 `registry`와 `yaml_editor` 인스턴스를 전달하도록 수정.

**Step 5: 테스트 통과 확인**

Run: `.venv/bin/python -m pytest tests/test_web/test_engines_api.py -v`
Expected: ALL PASS

**Step 6: 전체 회귀 테스트**

Run: `.venv/bin/python -m pytest tests/ -v`

**Step 7: 커밋**

```bash
git add netwatcher/web/routes/engines.py netwatcher/web/server.py netwatcher/app.py tests/test_web/test_engines_api.py
git commit -m "feat(web): Engine 설정 REST API 추가 (조회/수정/토글)"
```

---

## Task 5: 프론트엔드 - Engines 탭

대시보드에 Engines 탭 추가. 엔진 목록 + 동적 설정 폼.

**Files:**
- Modify: `netwatcher/web/static/index.html` (Engines 탭 HTML)
- Modify: `netwatcher/web/static/js/app.js` (Engines 탭 로직)
- Modify: `netwatcher/web/static/css/style.css` (Engines 탭 스타일)

**Step 1: index.html에 Engines 탭 추가**

탭 네비게이션에 Engines 버튼 추가 (line 72 부근):
```html
<button class="tab" data-tab="engines">Engines</button>
```

Blocklist 탭 `</section>` 이후에 Engines 탭 컨텐츠 추가:
```html
<!-- Engines Tab -->
<section id="tab-engines" class="tab-content">
    <div class="engines-layout">
        <div class="engines-list" id="engines-list"></div>
        <div class="engine-detail" id="engine-detail">
            <div class="engine-detail-empty">Select an engine to configure</div>
        </div>
    </div>
</section>
```

**Step 2: app.js에 Engines 탭 로직 추가**

기존 탭 클릭 핸들러(line 177-187)에 engines 탭 조건 추가:
```javascript
if (tab.dataset.tab === "engines") loadEngines();
```

Engines 관련 함수들 (blocklist 섹션 이후에 추가):
```javascript
// === ENGINES TAB ===
var enginesData = [];
var selectedEngine = null;

async function loadEngines() {
    try {
        var resp = await authFetch(API + "/api/engines");
        var data = await resp.json();
        enginesData = data.engines;
        renderEnginesList();
        if (selectedEngine) {
            var found = enginesData.find(function(e) { return e.name === selectedEngine; });
            if (found) renderEngineDetail(found);
        }
    } catch (e) {
        console.error("Failed to load engines:", e);
    }
}

function renderEnginesList() {
    var container = document.getElementById("engines-list");
    container.innerHTML = "";
    enginesData.forEach(function (eng) {
        var card = document.createElement("div");
        card.className = "engine-card" + (eng.name === selectedEngine ? " selected" : "");
        card.innerHTML =
            '<div class="engine-card-header">' +
            '<span class="engine-card-name">' + esc(eng.name) + '</span>' +
            '<label class="toggle-switch">' +
            '<input type="checkbox"' + (eng.enabled ? ' checked' : '') + ' />' +
            '<span class="toggle-slider"></span>' +
            '</label>' +
            '</div>';

        // 카드 클릭 → 상세 설정 표시
        card.addEventListener("click", function (e) {
            if (e.target.tagName === "INPUT") return; // 토글 클릭 무시
            selectedEngine = eng.name;
            renderEnginesList();
            renderEngineDetail(eng);
        });

        // 토글 변경
        var toggle = card.querySelector("input[type=checkbox]");
        toggle.addEventListener("change", function () {
            toggleEngine(eng.name, this.checked);
        });

        container.appendChild(card);
    });
}

function renderEngineDetail(eng) {
    var container = document.getElementById("engine-detail");
    var schema = eng.schema || [];
    var config = eng.config || {};

    var html = '<h3>' + esc(eng.name) + '</h3>';
    html += '<form id="engine-config-form">';

    schema.forEach(function (field) {
        if (field.key === "enabled") return; // 토글로 이미 처리
        var val = config[field.key];
        if (val === undefined || val === null) val = field.default;

        html += '<div class="engine-field">';
        html += '<label class="engine-field-label">' + esc(field.label) + '</label>';
        if (field.description) {
            html += '<div class="engine-field-desc">' + esc(field.description) + '</div>';
        }

        if (field.type === "bool") {
            html += '<label class="toggle-switch"><input type="checkbox" name="' + esc(field.key) + '"'
                + (val ? ' checked' : '') + ' data-type="bool" /><span class="toggle-slider"></span></label>';
        } else if (field.type === "int" || field.type === "float") {
            var step = field.type === "float" ? '0.01' : '1';
            html += '<input type="number" class="input-search engine-input" name="' + esc(field.key) + '"'
                + ' value="' + val + '" step="' + step + '"'
                + (field.min !== null ? ' min="' + field.min + '"' : '')
                + (field.max !== null ? ' max="' + field.max + '"' : '')
                + ' data-type="' + field.type + '" />';
        } else if (field.type === "list") {
            var listVal = Array.isArray(val) ? val.join(", ") : String(val || "");
            html += '<input type="text" class="input-search engine-input" name="' + esc(field.key) + '"'
                + ' value="' + esc(listVal) + '" placeholder="comma separated" data-type="list" />';
        } else {
            html += '<input type="text" class="input-search engine-input" name="' + esc(field.key) + '"'
                + ' value="' + esc(String(val)) + '" data-type="str" />';
        }

        html += '</div>';
    });

    html += '<div class="engine-form-actions">';
    html += '<button type="submit" class="btn btn-accent">Save</button>';
    html += '<span id="engine-save-status" class="engine-save-status"></span>';
    html += '</div>';
    html += '</form>';

    container.innerHTML = html;

    // 폼 제출
    document.getElementById("engine-config-form").addEventListener("submit", function (e) {
        e.preventDefault();
        saveEngineConfig(eng.name);
    });
}

async function saveEngineConfig(name) {
    var form = document.getElementById("engine-config-form");
    var inputs = form.querySelectorAll("input[name]");
    var body = {};

    inputs.forEach(function (input) {
        var key = input.name;
        var type = input.dataset.type;
        if (type === "bool") {
            body[key] = input.checked;
        } else if (type === "int") {
            body[key] = parseInt(input.value) || 0;
        } else if (type === "float") {
            body[key] = parseFloat(input.value) || 0;
        } else if (type === "list") {
            body[key] = input.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
            // 숫자 리스트 감지
            if (body[key].length > 0 && body[key].every(function (v) { return !isNaN(v); })) {
                body[key] = body[key].map(Number);
            }
        } else {
            body[key] = input.value;
        }
    });

    var status = document.getElementById("engine-save-status");
    status.textContent = "Saving...";
    status.className = "engine-save-status";

    try {
        var resp = await authFetch(API + "/api/engines/" + name + "/config", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        if (resp.ok) {
            status.textContent = "Saved";
            status.className = "engine-save-status success";
            loadEngines();
        } else {
            var data = await resp.json();
            status.textContent = data.error || "Save failed";
            status.className = "engine-save-status error";
        }
    } catch (e) {
        status.textContent = "Error: " + e.message;
        status.className = "engine-save-status error";
    }
}

async function toggleEngine(name, enabled) {
    try {
        var resp = await authFetch(API + "/api/engines/" + name + "/toggle", {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: enabled }),
        });
        if (resp.ok) loadEngines();
    } catch (e) {
        console.error("Failed to toggle engine:", e);
        loadEngines(); // 롤백 UI
    }
}
```

**Step 3: CSS 스타일 추가**

`netwatcher/web/static/css/style.css`에 engines 관련 스타일 추가:

```css
/* Engines tab layout */
.engines-layout {
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 16px;
    min-height: 500px;
}
.engines-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    overflow-y: auto;
    max-height: 70vh;
}
.engine-card {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    cursor: pointer;
    transition: border-color 0.2s;
}
.engine-card:hover { border-color: var(--accent); }
.engine-card.selected { border-color: var(--accent); background: rgba(52,152,219,0.08); }
.engine-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.engine-card-name { font-weight: 600; font-size: 14px; }

/* Toggle switch */
.toggle-switch { position: relative; display: inline-block; width: 40px; height: 22px; }
.toggle-switch input { opacity: 0; width: 0; height: 0; }
.toggle-slider {
    position: absolute; cursor: pointer; inset: 0;
    background: #4a4d65; border-radius: 22px; transition: 0.3s;
}
.toggle-slider::before {
    content: ""; position: absolute; height: 16px; width: 16px;
    left: 3px; bottom: 3px; background: white; border-radius: 50%; transition: 0.3s;
}
.toggle-switch input:checked + .toggle-slider { background: var(--accent); }
.toggle-switch input:checked + .toggle-slider::before { transform: translateX(18px); }

/* Engine detail form */
.engine-detail {
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
}
.engine-detail-empty { color: var(--text-dim); text-align: center; padding: 40px 0; }
.engine-field { margin-bottom: 16px; }
.engine-field-label { display: block; font-weight: 600; font-size: 13px; margin-bottom: 4px; }
.engine-field-desc { font-size: 12px; color: var(--text-dim); margin-bottom: 6px; }
.engine-input { width: 100%; max-width: 300px; }
.engine-form-actions { margin-top: 20px; display: flex; align-items: center; gap: 12px; }
.engine-save-status { font-size: 13px; }
.engine-save-status.success { color: var(--success, #2ed573); }
.engine-save-status.error { color: var(--critical); }
```

**Step 4: 수동 검증**

브라우저에서 `http://localhost:38585` → Engines 탭 클릭 → 엔진 목록 로드 확인 → 엔진 선택 → 설정 폼 렌더링 확인 → 값 변경 후 Save → 성공 메시지 확인

**Step 5: filter-engine 드롭다운 동적화**

`index.html`의 하드코딩된 엔진 필터(lines 83-97)를 JS에서 동적으로 채우도록 수정:

```html
<!-- 기존 하드코딩된 option 제거, All Engines만 남김 -->
<select id="filter-engine">
    <option value="">All Engines</option>
</select>
```

`app.js`의 `loadEvents()` 또는 `initApp()`에서 엔진 목록을 API로 가져와 옵션 채우기:

```javascript
async function populateEngineFilter() {
    try {
        var resp = await authFetch(API + "/api/engines");
        var data = await resp.json();
        var select = document.getElementById("filter-engine");
        // 기존 옵션 유지 (All Engines)
        while (select.options.length > 1) select.remove(1);
        data.engines.forEach(function (eng) {
            var opt = document.createElement("option");
            opt.value = eng.name;
            opt.textContent = eng.name.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
            select.appendChild(opt);
        });
    } catch (e) {
        // 실패 시 기존 하드코딩 폴백 불필요 (API가 없으면 빈 상태)
    }
}
```

`initApp()`에 `populateEngineFilter()` 호출 추가.

**Step 6: 커밋**

```bash
git add netwatcher/web/static/index.html netwatcher/web/static/js/app.js netwatcher/web/static/css/style.css
git commit -m "feat(web): Engines 설정 탭 UI 추가 (동적 폼 + 토글)"
```

---

## Task 6: app.py 통합 + 전체 테스트

`NetWatcher` 클래스에서 `YamlConfigEditor`를 생성하고 `create_app()`에 전달.

**Files:**
- Modify: `netwatcher/app.py`
- Test: 전체 테스트 실행

**Step 1: app.py 수정**

`NetWatcher.__init__()` 또는 `start()` 메서드에서:

```python
from netwatcher.utils.yaml_editor import YamlConfigEditor

# config_path 결정 (Config.load와 동일한 로직)
config_path = os.environ.get("NETWATCHER_CONFIG", "config/default.yaml")
self._yaml_editor = YamlConfigEditor(config_path)
```

`create_app()` 호출 시 `registry=self._registry, yaml_editor=self._yaml_editor` 전달.

**Step 2: 전체 테스트 실행**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: ALL PASS (기존 571 + 신규 ~20)

**Step 3: 커밋**

```bash
git add netwatcher/app.py
git commit -m "feat(app): YamlConfigEditor 통합, create_app에 registry/editor 전달"
```
