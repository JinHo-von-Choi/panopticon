"""실행 사용자 전용 저장소의 서명을 확인한 모델만 읽는다."""

import hmac
import os
import re
import secrets
import stat
from pathlib import Path

MAGIC = b"PANOPTICON-MODEL-1\n"
MAX_BYTES = 64 * 1024 * 1024
KEY_NAME = ".artifact-key"


def validate_name(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name):
        raise ValueError("Invalid model name")


def open_directory(path: Path, *, create=False):
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(descriptor)
        raise ValueError("Model directory must be owned by the current user with mode 0700")
    return descriptor


def read_private(directory, name, limit):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > limit):
            raise ValueError("Invalid model artifact permissions or size")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Model artifact exceeds capacity")
        return data


def get_key(directory, *, create=False):
    if create:
        try:
            descriptor = os.open(KEY_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        except FileExistsError:
            pass  # Another save already created the private key.
        else:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
    key = read_private(directory, KEY_NAME, 32)
    if len(key) != 32:
        raise ValueError("Invalid model artifact key")
    return key


def atomic_write(directory, name, data):
    temporary = ".model-" + secrets.token_hex(16)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass  # Atomic replacement removed the temporary entry.


def sign(name, payload, key):
    if len(payload) > MAX_BYTES:
        raise ValueError("Model artifact exceeds capacity")
    tag = hmac.digest(key, MAGIC + name.encode("ascii") + b"\0" + payload, "sha256")
    return MAGIC + tag + payload


def verify(name, data, key):
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 32:
        raise ValueError("Unsigned model artifact; retrain the experimental model")
    tag, payload = data[len(MAGIC):len(MAGIC) + 32], data[len(MAGIC) + 32:]
    expected = hmac.digest(key, MAGIC + name.encode("ascii") + b"\0" + payload, "sha256")
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Model artifact authentication failed")
    return payload
