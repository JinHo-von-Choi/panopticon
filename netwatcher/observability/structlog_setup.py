"""structlog 기반 구조화된 로깅 설정.

stdlib logging을 structlog으로 래핑하여 JSON 또는 콘솔 출력을 지원한다.
컨텍스트 변수(trace_id, engine_name, source_ip)를 바인딩할 수 있다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from netwatcher.utils.config import Config


def _add_caller_info(
    logger: Any, method_name: str, event_dict: dict[str, Any],
) -> dict[str, Any]:
    """stdlib LogRecord에서 호출자 정보를 추출한다."""
    record = event_dict.get("_record")
    if record is not None:
        event_dict["logger"] = record.name
    return event_dict


def setup_structlog(config: Config) -> structlog.stdlib.BoundLogger:
    """structlog을 초기화하고 stdlib logging과 통합한다.

    Args:
        config: NetWatcher 설정 객체.

    Returns:
        루트 바운드 로거.
    """
    log_format   = config.get("observability.log_format", config.get("logging.format", "json"))
    level_str    = config.get("logging.level", "INFO")
    log_dir      = Path(config.get("logging.directory", "data/logs"))
    max_bytes    = config.get("logging.max_bytes", 10_485_760)
    backup_count = config.get("logging.backup_count", 5)

    log_dir.mkdir(parents=True, exist_ok=True)

    # structlog 프로세서 체인
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if log_format == "console":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer(ensure_ascii=False)

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # stdlib ProcessorFormatter (structlog 이벤트를 최종 렌더링)
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            _add_caller_info,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    # 루트 로거 설정
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(getattr(logging, level_str.upper(), logging.INFO))

    # 콘솔 핸들러
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # 로테이팅 파일 핸들러
    file_handler = RotatingFileHandler(
        log_dir / "netwatcher.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # netwatcher 로거 레벨 설정
    nw_logger = logging.getLogger("netwatcher")
    nw_logger.setLevel(getattr(logging, level_str.upper(), logging.INFO))

    return structlog.get_logger("netwatcher")


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """명명된 structlog 로거를 반환한다.

    Args:
        name: 로거 이름 (예: "netwatcher.detection.arp_spoof").

    Returns:
        BoundLogger 인스턴스.
    """
    return structlog.get_logger(name)
