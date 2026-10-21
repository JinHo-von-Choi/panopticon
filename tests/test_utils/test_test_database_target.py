"""테스트 하네스가 지정한 DB 대상이 환경변수로 바뀌지 않는지 검증한다.

Config.load()는 NETWATCHER_DB_* 환경변수를 YAML 뒤에 덮어쓴다. 개발자의 .env
에 운영 DB가 적혀 있으면 시험 스키마가 그 DB에 만들어지고 지워진다. 시험
하네스는 로드 직후 postgresql 구간을 다시 고정해 이 경로를 막는다.
"""

from __future__ import annotations

import os

import asyncpg
import pytest

from netwatcher.utils.config import Config


def _write_config(tmp_path, host: str, port: int, database: str) -> str:
    path = tmp_path / "target.yaml"
    path.write_text(
        f"netwatcher:\n"
        f"  postgresql:\n"
        f"    host: \"{host}\"\n"
        f"    port: {port}\n"
        f"    database: \"{database}\"\n"
        f"    username: \"user\"\n"
        f"    password: \"pass\"\n",
        encoding="utf-8",
    )
    return str(path)


def test_env_override_wins_over_yaml(tmp_path, monkeypatch):
    """환경변수가 YAML 을 덮어쓰는 동작 자체를 고정한다."""
    monkeypatch.setenv("NETWATCHER_DB_HOST", "env-host")
    monkeypatch.setenv("NETWATCHER_DB_NAME", "env-db")
    config = Config.load(_write_config(tmp_path, "yaml-host", 5432, "yaml-db"))

    assert config.get("postgresql.host") == "env-host"
    assert config.get("postgresql.database") == "env-db"


def test_config_fixture_pins_test_database(config):
    """시험 픽스처는 환경변수가 가리키는 DB가 아니라 지정된 시험 DB를 쓴다."""
    section = config.section("postgresql")

    assert section["host"] == os.environ.get("NETWATCHER_TEST_DB_HOST", "localhost")
    assert section["database"] == os.environ.get("NETWATCHER_TEST_DB_NAME", "netwatcher_test")
    assert section["username"] == os.environ.get("NETWATCHER_TEST_DB_USER", "netwatcher")
    assert section["port"] == int(os.environ.get("NETWATCHER_TEST_DB_PORT", "5432"))


def test_config_fixture_ignores_runtime_db_env(config, monkeypatch):
    """NETWATCHER_DB_* 로 시험 DB 대상이 바뀌지 않는다."""
    from tests.conftest import _TEST_DB

    monkeypatch.setenv("NETWATCHER_DB_HOST", "some-other-host")
    monkeypatch.setenv("NETWATCHER_DB_NAME", "some-other-db")

    # Config.load() 는 환경변수를 반영한다 — 그래서 시험 하네스가 다시 고정한다.
    reloaded = Config.load(config.config_path)
    assert reloaded.get("postgresql.host") == "some-other-host"

    # 시험 하네스가 쓰는 값은 .env 가 아니라 지정된 시험 DB 다.
    assert _TEST_DB["host"] == os.environ.get("NETWATCHER_TEST_DB_HOST", "localhost")
    assert _TEST_DB["database"] == os.environ.get(
        "NETWATCHER_TEST_DB_NAME", "netwatcher_test"
    )


def test_db_skip_is_opt_in(monkeypatch):
    """DB 부재 시 건너뛰기는 기본이 아니다 — 명시적으로 허용해야 한다."""
    from tests.conftest import _allow_db_skip

    monkeypatch.delenv("NETWATCHER_TEST_ALLOW_DB_SKIP", raising=False)
    assert _allow_db_skip() is False

    monkeypatch.setenv("NETWATCHER_TEST_ALLOW_DB_SKIP", "1")
    assert _allow_db_skip() is True

    monkeypatch.setenv("NETWATCHER_TEST_ALLOW_DB_SKIP", "false")
    assert _allow_db_skip() is False


@pytest.mark.asyncio
async def test_unreachable_database_fails_without_retry_wait(config):
    """재시도 횟수를 1로 두면 도달 불가 DB 에서 즉시 실패한다."""
    import time

    from netwatcher.storage.database import Database

    broken = Config.load(config.config_path)
    broken.raw["postgresql"] = {
        **broken.raw["postgresql"],
        "host": "127.0.0.1",
        "port": 1,
    }

    database = Database(broken)
    started = time.monotonic()
    with pytest.raises((OSError, asyncpg.PostgresError)):
        await database.connect(max_retries=1)
    assert time.monotonic() - started < 5.0
