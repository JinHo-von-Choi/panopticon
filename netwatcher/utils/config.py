"""기본값 병합 기능을 갖춘 YAML 설정 로더."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

# 환경변수 → Config 경로 매핑
_ENV_OVERRIDES: list[tuple[str, str, type]] = [
    ("NETWATCHER_DB_HOST", "postgresql.host", str),
    ("NETWATCHER_DB_PORT", "postgresql.port", int),
    ("NETWATCHER_DB_NAME", "postgresql.database", str),
    ("NETWATCHER_DB_USER", "postgresql.username", str),
    ("NETWATCHER_DB_PASSWORD", "postgresql.password", str),
    ("NETWATCHER_SLACK_WEBHOOK_URL", "alerts.channels.slack.webhook_url", str),
    ("NETWATCHER_SLACK_DASHBOARD_URL", "alerts.channels.slack.dashboard_url", str),
    ("NETWATCHER_LOGIN_ENABLED", "auth.enabled", str),
    ("NETWATCHER_LOGIN_USERNAME", "auth.username", str),
    ("NETWATCHER_LOGIN_PASSWORD", "auth.password", str),
    ("NETWATCHER_JWT_SECRET", "auth.jwt_secret", str),
    ("NETWATCHER_DISCORD_WEBHOOK_URL", "alerts.channels.discord.webhook_url", str),
    ("NETWATCHER_TELEGRAM_BOT_TOKEN", "alerts.channels.telegram.bot_token", str),
    ("NETWATCHER_TELEGRAM_CHAT_ID", "alerts.channels.telegram.chat_id", str),
]


def _deep_merge(base: dict, override: dict) -> dict:
    """override를 base에 재귀적으로 병합하여 새 dict를 반환한다."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _set_nested(data: dict, dotted_key: str, value: Any) -> None:
    """점 표기법을 사용하여 중첩 dict에 값을 설정한다."""
    keys = dotted_key.split(".")
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def _apply_env_overrides(data: dict) -> None:
    """환경변수가 설정되어 있으면 YAML 값을 오버라이드한다."""
    for env_var, config_path, cast in _ENV_OVERRIDES:
        value = os.environ.get(env_var)
        if value is not None:
            _set_nested(data, config_path, cast(value))


class Config:
    """YAML 파일에서 로드된 불변 설정 컨테이너."""

    def __init__(self, data: dict[str, Any], config_path: str | Path | None = None) -> None:
        self._data = data
        self.config_path: str | None = str(config_path) if config_path else None

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> Config:
        """YAML 파일에서 설정을 로드한다.

        프로젝트 루트 기준 config/default.yaml을 기본 경로로 사용한다.
        환경변수 NETWATCHER_CONFIG로 경로를 오버라이드할 수 있다.
        .env 파일이 존재하면 자동으로 로드하여 환경변수를 설정한다.
        """
        load_dotenv()

        if config_path is None:
            config_path = os.environ.get("NETWATCHER_CONFIG")
        if config_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            config_path = project_root / "config" / "default.yaml"

        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        inner = data.get("netwatcher", data)
        _apply_env_overrides(inner)

        return cls(inner, config_path=config_path)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """점 표기법으로 값을 조회한다: 'web.port' -> config['web']['port']."""
        keys = dotted_key.split(".")
        current = self._data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current

    def section(self, key: str) -> dict[str, Any]:
        """주어진 최상위 키에 대한 하위 dict를 반환한다."""
        return self._data.get(key, {})

    @property
    def raw(self) -> dict[str, Any]:
        """설정 데이터의 원본 dict를 반환한다."""
        return self._data
