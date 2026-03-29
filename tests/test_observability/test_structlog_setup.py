"""structlog 설정 테스트: JSON 출력, 컨텍스트 바인딩 검증."""

from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest
import structlog

from netwatcher.utils.config import Config


def _make_config(tmp_path: Path, log_format: str = "json") -> Config:
    """테스트용 Config를 생성한다."""
    yaml_content = f"""
netwatcher:
  logging:
    level: DEBUG
    directory: "{tmp_path / 'logs'}"
    max_bytes: 1048576
    backup_count: 1
  observability:
    structlog: true
    log_format: "{log_format}"
"""
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(yaml_content)
    return Config.load(config_file)


@pytest.fixture(autouse=True)
def _reset_structlog():
    """각 테스트 전후로 structlog과 루트 로거를 리셋한다."""
    yield
    structlog.reset_defaults()
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)


class TestStructlogSetup:
    """structlog 설정 테스트 스위트."""

    def test_json_output_format(self, tmp_path: Path) -> None:
        """JSON 포맷 출력이 유효한 JSON인지 검증한다."""
        from netwatcher.observability.structlog_setup import setup_structlog

        config = _make_config(tmp_path, "json")
        setup_structlog(config)

        # stdout 핸들러를 StringIO로 교체
        buf = StringIO()
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler) and not hasattr(
                handler, "baseFilename"
            ):
                handler.stream = buf
                break

        logger = structlog.get_logger("test.json")
        logger.info("test_event", key="value")

        output = buf.getvalue().strip()
        assert output, "로그 출력이 비어있다"

        parsed = json.loads(output)
        assert parsed["event"] == "test_event"
        assert parsed["key"] == "value"
        assert "level" in parsed
        assert "timestamp" in parsed

    def test_console_output_format(self, tmp_path: Path) -> None:
        """콘솔 포맷이 사람이 읽을 수 있는 형식인지 검증한다."""
        from netwatcher.observability.structlog_setup import setup_structlog

        config = _make_config(tmp_path, "console")
        setup_structlog(config)

        buf = StringIO()
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler) and not hasattr(
                handler, "baseFilename"
            ):
                handler.stream = buf
                break

        logger = structlog.get_logger("test.console")
        logger.info("console_event")

        output = buf.getvalue().strip()
        assert output, "콘솔 로그 출력이 비어있다"
        # JSON이 아님을 확인
        with pytest.raises(json.JSONDecodeError):
            json.loads(output)

    def test_context_binding(self, tmp_path: Path) -> None:
        """바운드 컨텍스트 변수가 로그 출력에 포함되는지 검증한다."""
        from netwatcher.observability.structlog_setup import setup_structlog

        config = _make_config(tmp_path, "json")
        setup_structlog(config)

        buf = StringIO()
        root = logging.getLogger()
        for handler in root.handlers:
            if isinstance(handler, logging.StreamHandler) and not hasattr(
                handler, "baseFilename"
            ):
                handler.stream = buf
                break

        logger = structlog.get_logger("test.context")
        bound  = logger.bind(
            trace_id="abc-123",
            engine_name="arp_spoof",
            source_ip="192.168.1.100",
        )
        bound.info("bound_event")

        output = buf.getvalue().strip()
        parsed = json.loads(output)
        assert parsed["trace_id"] == "abc-123"
        assert parsed["engine_name"] == "arp_spoof"
        assert parsed["source_ip"] == "192.168.1.100"

    def test_get_logger(self, tmp_path: Path) -> None:
        """get_logger가 BoundLogger를 반환하는지 검증한다."""
        from netwatcher.observability.structlog_setup import get_logger, setup_structlog

        config = _make_config(tmp_path, "json")
        setup_structlog(config)

        logger = get_logger("netwatcher.test")
        assert logger is not None

    def test_log_file_created(self, tmp_path: Path) -> None:
        """로그 파일이 생성되는지 검증한다."""
        from netwatcher.observability.structlog_setup import setup_structlog

        config = _make_config(tmp_path, "json")
        setup_structlog(config)

        logger = structlog.get_logger("test.file")
        logger.info("file_event")

        log_file = tmp_path / "logs" / "netwatcher.log"
        assert log_file.exists()
        content = log_file.read_text()
        assert "file_event" in content
