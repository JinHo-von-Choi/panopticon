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
    args = parser.parse_args()

    from netwatcher.utils.config import Config
    from netwatcher.app import NetWatcher

    config = Config.load(args.config)
    app = NetWatcher(config)

    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
