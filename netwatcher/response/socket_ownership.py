"""소유 기록과 프로세스 잠금으로 강제 종료 후 Unix 소켓을 회수한다."""

import fcntl
import json
import os
from pathlib import Path
import stat


class SocketOwnership:
    def __init__(self, path: Path):
        self.path = path
        self.fd = None

    @staticmethod
    def identity(info):
        return [info.st_dev, info.st_ino, info.st_ctime_ns]

    def acquire(self):
        lock = self.path.with_name(self.path.name + '.lock')
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise ValueError('socket ownership file must be owned and private')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('socket server is already running') from None
            try:
                current = self.path.lstat()
            except FileNotFoundError:
                current = None
            if current is not None:
                raw = os.read(fd, 256)
                try:
                    recorded = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    raise ValueError('existing socket ownership is unconfirmed') from None
                if (not stat.S_ISSOCK(current.st_mode) or current.st_uid != os.getuid()
                        or recorded != self.identity(current)):
                    raise ValueError('existing socket ownership is unconfirmed')
                # 전용 디렉터리의 쓰기 권한은 같은 서비스 UID에만 있다.
                if self.identity(self.path.lstat()) != recorded:
                    raise ValueError('socket changed during recovery')
                self.path.unlink()
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def record(self):
        if self.fd is None:
            raise RuntimeError('socket ownership lock is not held')
        payload = json.dumps(self.identity(self.path.lstat())).encode()
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.ftruncate(self.fd, 0)
        if os.write(self.fd, payload) != len(payload):
            raise OSError('socket ownership record is incomplete')
        os.fsync(self.fd)

    def release(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
