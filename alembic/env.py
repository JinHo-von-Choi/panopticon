"""Alembic environment configuration for NetWatcher.

DB 접속 정보를 환경변수(NETWATCHER_DB_*) 또는 config YAML에서 로드한다.
search_path를 설정하여 올바른 스키마에 마이그레이션을 적용한다.
"""

from __future__ import annotations

import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import create_engine, pool, text

load_dotenv()

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _build_database_url() -> str:
    """환경변수 또는 config YAML에서 PostgreSQL URL을 조합한다."""
    host     = os.environ.get("NETWATCHER_DB_HOST", "localhost")
    port     = os.environ.get("NETWATCHER_DB_PORT", "5432")
    database = os.environ.get("NETWATCHER_DB_NAME", "netwatcher")
    user     = os.environ.get("NETWATCHER_DB_USER", "home")
    password = os.environ.get("NETWATCHER_DB_PASSWORD", "")

    # YAML config fallback (환경변수가 없을 경우)
    if not any(os.environ.get(k) for k in (
        "NETWATCHER_DB_HOST", "NETWATCHER_DB_PORT", "NETWATCHER_DB_NAME",
        "NETWATCHER_DB_USER", "NETWATCHER_DB_PASSWORD",
    )):
        try:
            from netwatcher.utils.config import Config
            cfg = Config.load()
            pg  = cfg.section("postgresql")
            host     = pg.get("host", host)
            port     = pg.get("port", port)
            database = pg.get("database", database)
            user     = pg.get("username", user)
            password = pg.get("password", password)
        except Exception:
            pass

    if password:
        from urllib.parse import quote_plus
        password = quote_plus(str(password))
        return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"
    return f"postgresql+psycopg2://{user}@{host}:{port}/{database}"


def _get_search_path() -> str:
    """search_path를 환경변수 또는 config에서 가져온다."""
    search_path = os.environ.get("NETWATCHER_DB_SEARCH_PATH")
    if search_path:
        return search_path

    try:
        from netwatcher.utils.config import Config
        cfg = Config.load()
        pg  = cfg.section("postgresql")
        return pg.get("search_path", "netwatcher,public")
    except Exception:
        return "netwatcher,public"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (SQL 출력만)."""
    url = _build_database_url()
    context.configure(
        url=url,
        target_metadata=None,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (실제 DB 연결)."""
    url          = _build_database_url()
    search_path  = _get_search_path()
    schema_name  = search_path.split(",")[0].strip()

    connectable = create_engine(
        url,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # 스키마가 없으면 생성
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
        connection.execute(text(f"SET search_path TO {search_path}"))
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=None,
            version_table_schema=schema_name,
        )

        with context.begin_transaction():
            connection.execute(text(f"SET search_path TO {search_path}"))
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
