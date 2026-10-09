"""진입점: python -m netwatcher"""

from __future__ import annotations

import argparse
import asyncio
import sys


def main() -> None:
    """NetWatcher CLI 진입점. 설정을 로드하고 애플리케이션을 실행한다."""
    parser = argparse.ArgumentParser(
        prog="netwatcher",
        description="NetWatcher - Local Network Packet Monitoring System",
    )
    parser.add_argument(
        "-c", "--config",
        default=None,
        help="Path to configuration YAML file (default: config/default.yaml)",
    )
    parser.add_argument("--component", choices=("console", "sensor", "executor"), default="console",
                        help="실행할 프로세스: 콘솔, 독립 센서 또는 조치 실행기")
    args = parser.parse_args()

    from netwatcher.utils.config import Config
    config = Config.load(args.config)
    mode = config.get("input.mode", "native")
    if args.component == "executor":
        from netwatcher.response.runtime import ExecutionWorker
        app = ExecutionWorker(config)
    elif args.component == "sensor":
        if mode != "native":
            parser.error("sensor requires input.mode: native")
        from netwatcher.app import NetWatcher
        app = NetWatcher(config, sensor_only=True)
    elif mode == "eve":
        from netwatcher.ingest.runtime import EveConsole
        app = EveConsole(config)
    elif mode == "native":
        console = config.get("native.console", {})
        if not isinstance(console, dict) or type(console.get("separate", True)) is not bool:
            parser.error("native.console.separate must be boolean")
        if console.get("separate", True) is not True:
            parser.error("native 모드는 독립 콘솔과 --component sensor로 실행해야 합니다. "
                         "native.console.separate: false는 지원하지 않습니다.")
        if not isinstance(config.get("native.control"), dict) or config.get("native.control.enabled") is not True:
            parser.error("native 콘솔에는 native.control.enabled: true와 센서 소켓 연결 설정이 필요합니다.")
        from netwatcher.native_console import NativeConsole
        app = NativeConsole(config)
    else:
        parser.error("input.mode must be eve or native")

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
