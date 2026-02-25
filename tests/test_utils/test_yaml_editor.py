"""YamlConfigEditor 단위 테스트."""

from __future__ import annotations

from pathlib import Path

import pytest

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


@pytest.fixture
def yaml_file(tmp_path: Path) -> Path:
    """tmp_path에 샘플 YAML 파일을 생성한다."""
    p = tmp_path / "config.yaml"
    p.write_text(SAMPLE_YAML)
    return p


class TestUpdateEngineConfig:
    """update_engine_config 관련 테스트."""

    def test_update_engine_config(self, yaml_file: Path) -> None:
        """지정한 키만 업데이트되고, 다른 엔진 설정은 변경되지 않는다."""
        editor = YamlConfigEditor(str(yaml_file))
        editor.update_engine_config("port_scan", {"threshold": 30, "window_seconds": 120})

        updated = editor.get_engine_config("port_scan")
        assert updated is not None
        assert updated["threshold"] == 30
        assert updated["window_seconds"] == 120
        assert updated["enabled"] is True  # 변경하지 않은 키는 유지

        dns = editor.get_engine_config("dns_anomaly")
        assert dns is not None
        assert dns["entropy_threshold"] == 3.8  # 다른 엔진은 영향 없음

    def test_update_creates_backup(self, yaml_file: Path) -> None:
        """.bak 백업 파일이 원본 내용으로 생성된다."""
        original_content = yaml_file.read_text()
        editor = YamlConfigEditor(str(yaml_file))
        editor.update_engine_config("port_scan", {"threshold": 99})

        bak = yaml_file.with_suffix(".yaml.bak")
        assert bak.exists()
        assert bak.read_text() == original_content

    def test_toggle_enabled(self, yaml_file: Path) -> None:
        """enabled 필드를 토글할 수 있다."""
        editor = YamlConfigEditor(str(yaml_file))

        editor.update_engine_config("port_scan", {"enabled": False})
        cfg = editor.get_engine_config("port_scan")
        assert cfg is not None
        assert cfg["enabled"] is False

        editor.update_engine_config("port_scan", {"enabled": True})
        cfg = editor.get_engine_config("port_scan")
        assert cfg is not None
        assert cfg["enabled"] is True


class TestGetEngineConfig:
    """get_engine_config 관련 테스트."""

    def test_get_engine_config(self, yaml_file: Path) -> None:
        """정상적으로 엔진 설정값을 읽는다."""
        editor = YamlConfigEditor(str(yaml_file))
        cfg = editor.get_engine_config("port_scan")

        assert cfg is not None
        assert cfg["enabled"] is True
        assert cfg["window_seconds"] == 60
        assert cfg["threshold"] == 15

    def test_get_engine_config_not_found(self, yaml_file: Path) -> None:
        """존재하지 않는 엔진에 대해 None을 반환한다."""
        editor = YamlConfigEditor(str(yaml_file))
        assert editor.get_engine_config("nonexistent_engine") is None


class TestCommentsPreserved:
    """YAML 주석 보존 테스트."""

    def test_comments_preserved(self, yaml_file: Path) -> None:
        """인라인 주석과 파일 상단 주석이 업데이트 후에도 유지된다."""
        editor = YamlConfigEditor(str(yaml_file))
        editor.update_engine_config("port_scan", {"threshold": 50})

        content = yaml_file.read_text()
        assert "# sliding window" in content
        assert "# NetWatcher config" in content
