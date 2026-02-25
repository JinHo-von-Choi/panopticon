"""로테이팅 파일 핸들러와 선택적 JSON 포맷을 지원하는 로깅 설정."""

from __future__ import annotations

import json as json_mod
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from netwatcher.utils.config import Config

LOG_FORMAT  = "%(asctime)s [%(levelname)-8s] %(name)-25s %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class JSONFormatter(logging.Formatter):
    """기계 파싱 가능한 출력을 위한 구조화된 JSON 로그 포매터."""

    def format(self, record: logging.LogRecord) -> str:
        """로그 레코드를 JSON 문자열로 포맷한다."""
        log_obj = {
            "ts": self.formatTime(record, DATE_FORMAT),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json_mod.dumps(log_obj, ensure_ascii=False)


def setup_logging(config: Config) -> logging.Logger:
    """콘솔 + 로테이팅 파일 핸들러로 루트 로거를 설정한다."""
    level_str    = config.get("logging.level", "INFO")
    log_dir      = Path(config.get("logging.directory", "data/logs"))
    max_bytes    = config.get("logging.max_bytes", 10_485_760)
    backup_count = config.get("logging.backup_count", 5)
    log_format   = config.get("logging.format", "text")

    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger("netwatcher")
    root.setLevel(getattr(logging, level_str.upper(), logging.INFO))

    if log_format == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)

    # 콘솔 핸들러
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    # 로테이팅 파일 핸들러
    file_handler = RotatingFileHandler(
        log_dir / "netwatcher.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    return root
