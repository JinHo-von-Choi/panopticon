"""분리 Compose의 전용 볼륨을 초기화한다. 기존 센서 설정을 덮어쓰지 않는다."""

import argparse
import os
from pathlib import Path
import stat


def prepare_volumes(runtime=Path('/run/panopticon'), data=Path('/app/data'), source=Path('/app/config'), *, socket_gid=10001):
    if type(socket_gid) is not int or not 0 <= socket_gid < 2**32:
        raise ValueError('공유 그룹 번호를 확인하세요')
    owner = os.getuid()
    for directory in (runtime,data):
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or directory.resolve()!=directory or info.st_uid!=owner or info.st_mode & 0o022:
            raise ValueError('초기화 볼륨은 실행 사용자 소유의 실제 디렉터리여야 합니다')
    os.chown(runtime,-1,socket_gid)
    os.chmod(runtime,0o710)
    os.chmod(data,0o700)
    for name in ('logs','pcaps','threatfeeds','extracted'):
        path=data/name
        path.mkdir(mode=0o700,exist_ok=True)
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_mode & 0o022:
            raise ValueError('센서 저장 디렉터리의 소유권과 권한을 확인하세요')
        os.chmod(path,0o700)
    for name in ('sensor.yaml','threatfeeds.yaml'):
        path=data/name
        if path.exists() or path.is_symlink():
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=owner or info.st_mode & 0o077 or info.st_nlink!=1:
                raise ValueError('기존 센서 설정의 소유권과 권한을 확인하세요')
            continue
        payload=(source/name).read_bytes()
        with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as stream:
            stream.write(payload)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, default=Path('/run/panopticon'))
    parser.add_argument('--data', type=Path, default=Path('/app/data'))
    parser.add_argument('--source', type=Path, default=Path('/app/config'))
    parser.add_argument('--socket-gid', type=int, default=10001)
    args = parser.parse_args()
    prepare_volumes(args.runtime, args.data, args.source, socket_gid=args.socket_gid)
