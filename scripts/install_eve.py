"""새 EVE 설치의 설정과 자격증명을 생성한다. 기존 설치를 변경하지 않는다."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import stat
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netwatcher.ingest.eve import MAX_LINE_BYTES, decode_eve_line


def dotenv_value(value):
    """Compose와 python-dotenv가 읽는 단일 인용 문자열."""
    value = str(value)
    if any(character in value for character in ("\n", "\r", "\x00")):
        raise ValueError("설정 경로에 제어 문자를 사용할 수 없습니다.")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def database_port():
    for port in (5432, 15432, 25432, 0):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return probe.getsockname()[1]
            except OSError:
                continue
    raise ValueError("DB 공개 포트를 준비할 수 없습니다.")


def prepare_installation(output, eve_file, *, log_gid=None, username="admin"):
    output = Path(output).absolute()
    eve_file = Path(eve_file).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("설치 디렉터리가 이미 있습니다. 새 디렉터리를 지정하세요.")
    if not username or len(username) > 64 or any(character in username for character in "\n\r\x00"):
        raise ValueError("관리자 계정 이름을 확인하세요.")
    directory = os.open(eve_file.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(eve_file.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info, parent = os.fstat(descriptor), os.fstat(directory)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("EVE 입력은 일반 파일이어야 합니다.")
            gid = log_gid if log_gid is not None else info.st_gid
            if isinstance(gid, bool) or not isinstance(gid, int) or not 0 <= gid < 2**32:
                raise ValueError("로그 읽기 그룹 번호를 확인하세요.")
            readable = bool(info.st_mode & stat.S_IROTH) or (gid == info.st_gid and bool(info.st_mode & stat.S_IRGRP))
            traversable = bool(parent.st_mode & stat.S_IXOTH) or (gid == parent.st_gid and bool(parent.st_mode & stat.S_IXGRP))
            if not readable or not traversable:
                raise ValueError("컨테이너의 로그 읽기 그룹에 디렉터리 탐색·파일 읽기 권한이 필요합니다.")
            sample = os.pread(descriptor, MAX_LINE_BYTES + 1, 0)
            if b"\n" in sample:
                sample = sample[:sample.index(b"\n") + 1]
                try:
                    decode_eve_line(sample, sensor_id="preflight", source_id="preflight",
                                    generation=str(uuid.uuid4()), offset=0)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    raise ValueError("첫 로그 행이 지원하는 EVE 형식이 아닙니다.") from None
            elif len(sample) > MAX_LINE_BYTES:
                raise ValueError("첫 EVE 행이 입력 크기 제한을 넘습니다.")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
    values = {
        "COMPOSE_PROJECT_NAME": "panopticon-" + hashlib.sha256(str(output).encode()).hexdigest()[:10],
        "PANOPTICON_CONFIG_DIR": str(output / "config"),
        "PANOPTICON_ENV_FILE": str(output / ".env"),
        "PANOPTICON_EVE_DIR": str(eve_file.parent), "PANOPTICON_EVE_GID": str(gid),
        "PANOPTICON_DB_PUBLISH_PORT": str(database_port()),
        "NETWATCHER_DB_HOST": "db", "NETWATCHER_DB_PORT": "5432",
        "NETWATCHER_DB_NAME": "netwatcher", "NETWATCHER_DB_USER": "netwatcher",
        "NETWATCHER_DB_PASSWORD": secrets.token_hex(32),
        "NETWATCHER_LOGIN_ENABLED": "true", "NETWATCHER_LOGIN_USERNAME": username,
        "NETWATCHER_LOGIN_PASSWORD": secrets.token_urlsafe(32), "NETWATCHER_JWT_SECRET": secrets.token_hex(32),
    }
    config = {"netwatcher": {
        "input": {"mode": "eve", "eve": {"sources": [{"sensor_id": "suricata-1", "source_id": "office-eve",
                    "directory": "/var/log/suricata", "filename": eve_file.name}],
                    "retention": {"days": 30, "max_records": 250000, "max_bytes": 268435456}}},
        "postgresql": {"host": "db", "port": 5432, "database": "netwatcher", "username": "netwatcher",
                       "password": "", "pool_size": 5, "ssl_mode": "disable"},
        "web": {"host": "0.0.0.0", "port": 38585}, "auth": {"enabled": True},
        "logging": {"level": "INFO", "directory": "data/logs"},
    }}
    environment = "\n".join(f"{key}={dotenv_value(value)}" for key, value in values.items()) + "\n"
    output.mkdir(mode=0o700)
    (output / "config").mkdir(mode=0o755)
    (output / "config").chmod(0o755)
    path = output / ".env"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(environment)
    path.chmod(0o600)
    path = output / "config/default.yaml"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "w") as stream:
        json.dump(config, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    path.chmod(0o644)
    return output / ".env"


def main():
    parser = argparse.ArgumentParser(description="새 Suricata EVE 설치 설정을 생성합니다.")
    parser.add_argument("--eve-file", required=True)
    parser.add_argument("--output", default="installation")
    parser.add_argument("--log-gid", type=int)
    parser.add_argument("--username", default="admin")
    arguments = parser.parse_args()
    try:
        environment = prepare_installation(arguments.output, arguments.eve_file,
                                           log_gid=arguments.log_gid, username=arguments.username)
    except (ValueError, OSError) as error:
        parser.exit(1, "설정 생성 실패: " + (str(error) if isinstance(error, ValueError) else type(error).__name__) + "\n")
    print(f"설정 생성 완료: {environment.parent}")
    print(f"로그인 정보 파일: {environment}")


if __name__ == "__main__":
    main()
