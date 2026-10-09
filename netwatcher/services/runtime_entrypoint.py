"""systemd가 전달한 서비스별 자격증명을 읽어 지정된 구성요소를 실행한다."""

import argparse
import io
import os
from pathlib import Path
import re
import sys

from dotenv import dotenv_values

MAX_CREDENTIAL_BYTES = 32768


def load_credentials(directory):
    path = Path(directory) / 'runtime.env'
    with path.open('rb') as stream:
        payload = stream.read(MAX_CREDENTIAL_BYTES + 1)
    if len(payload) > MAX_CREDENTIAL_BYTES:
        raise ValueError('서비스 자격증명 파일이 너무 큽니다')
    values = dotenv_values(stream=io.StringIO(payload.decode('utf-8')), interpolate=False)
    if not values or any(not re.fullmatch(r'(?:NETWATCHER_[A-Z0-9_]+|PANOPTICON_DB_[A-Z0-9_]+)', key)
                         or value is None for key, value in values.items()):
        raise ValueError('서비스 자격증명 항목을 확인하세요')
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('component', choices=('sensor', 'console', 'roles', 'migrate', 'grants'))
    parser.add_argument('--config')
    args = parser.parse_args()
    values = load_credentials(os.environ['CREDENTIALS_DIRECTORY'])
    os.environ.update(values)
    os.environ['NETWATCHER_SKIP_DOTENV'] = '1'
    if args.component in ('sensor', 'console'):
        if not args.config:
            parser.error('구성요소의 설정 파일이 필요합니다')
        command = ['-m', 'netwatcher', '--component', args.component, '-c', args.config]
    elif args.component == 'migrate':
        command = ['-m', 'alembic', 'upgrade', 'head']
    else:
        command = ['-m', 'netwatcher.storage.runtime_roles', args.component]
    os.execv(sys.executable, [sys.executable, *command])


if __name__ == '__main__':
    main()
