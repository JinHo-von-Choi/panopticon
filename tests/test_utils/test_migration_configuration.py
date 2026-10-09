"""설정 오류 시 실제 Alembic 명령이 기본 DB로 진행하지 않는지 검증한다."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


def migration_environment(config_path):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("NETWATCHER_DB_")}
    env.update({"NETWATCHER_SKIP_DOTENV": "1", "NETWATCHER_CONFIG": str(config_path)})
    return env


@pytest.mark.parametrize("content", ["[must-not-leak-this-input", "- unsupported-root"])
def test_invalid_config_stops_offline_migration_without_leaking_input(tmp_path, content):
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text(content)
    result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
                            cwd=ROOT, env=migration_environment(config_path),
                            capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert "Migration configuration could not be loaded" in result.stderr
    assert "must-not-leak-this-input" not in result.stderr
    assert "CREATE TABLE" not in result.stdout


def test_missing_search_path_config_stops_before_database_connection(tmp_path):
    env = migration_environment(tmp_path / "missing.yaml")
    env.update({"NETWATCHER_DB_HOST": "127.0.0.1", "NETWATCHER_DB_PORT": "1",
                "NETWATCHER_DB_NAME": "isolated", "NETWATCHER_DB_USER": "test"})
    result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                            cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert "Migration search path configuration could not be loaded" in result.stderr
    assert "OperationalError" not in result.stderr
