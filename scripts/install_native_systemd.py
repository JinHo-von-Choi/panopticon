"""새 호스트 설치의 일반 사용자 센서·콘솔 설정과 systemd 서비스를 생성한다."""

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

from dotenv import dotenv_values

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.install_native import prepare_native_installation
from scripts.install_eve import dotenv_value
from netwatcher.storage.runtime_roles import identifier


def absolute_path(value):
    path = str(Path(value).absolute())
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', path) or '..' in Path(path).parts:
        raise ValueError('서비스 경로는 공백·제어 문자·상대 경로 요소 없이 지정하세요')
    return path


def read_database(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 32768):
            raise ValueError('DB 자격증명 파일은 소유자만 읽을 수 있는 일반 파일이어야 합니다')
        with os.fdopen(fd, 'r', closefd=False) as stream:
            values = dotenv_values(stream=stream, interpolate=False)
        keys = ('HOST', 'PORT', 'NAME', 'USER', 'PASSWORD')
        result = {f'NETWATCHER_DB_{key}': values.get(f'NETWATCHER_DB_{key}') for key in keys}
        if not all(isinstance(value, str) and value for value in result.values()):
            raise ValueError('DB 주소·포트·이름·관리 계정·비밀번호를 지정하세요')
        if not result['NETWATCHER_DB_PORT'].isdigit() or not 0 < int(result['NETWATCHER_DB_PORT']) < 65536:
            raise ValueError('DB 포트를 확인하세요')
        for value in result.values():
            dotenv_value(value)
        return result
    finally:
        os.close(fd)


def write_env(path, values):
    path.write_text('\n'.join(f'{key}={dotenv_value(value)}' for key, value in values.items()) + '\n')
    path.chmod(0o600)


def replace_data(value, state):
    if isinstance(value, dict):
        return {key: replace_data(item, state) for key, item in value.items()}
    if isinstance(value, list):
        return [replace_data(item, state) for item in value]
    return state + '/' + value[5:] if isinstance(value, str) and value.startswith('data/') else value


def prepare_systemd_installation(output, interface, *, database_env, console_user, sensor_user,
        source='/opt/panopticon', destination='/etc/panopticon-native', prefix='panopticon-native',
        schema='netwatcher', username='admin', sensor_id='office-native'):
    source, destination = absolute_path(source), absolute_path(destination)
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', prefix):
        raise ValueError('서비스 이름을 확인하세요')
    schema = identifier(schema)
    try:
        console, sensor = pwd.getpwnam(console_user), pwd.getpwnam(sensor_user)
    except KeyError:
        raise ValueError('콘솔과 센서의 전용 시스템 계정을 먼저 만드세요') from None
    if not console.pw_uid or not sensor.pw_uid or console.pw_uid == sensor.pw_uid:
        raise ValueError('콘솔과 센서는 서로 다른 일반 사용자여야 합니다')
    database = read_database(database_env)
    output = Path(absolute_path(output))
    prepare_native_installation(output, interface, username=username, sensor_id=sensor_id)
    runtime, sensor_state, console_state = '/run/' + prefix, '/var/lib/' + prefix + '-sensor', '/var/lib/' + prefix + '-console'
    for kind in ('console', 'sensor'):
        path = output / 'config' / (kind + '.yaml')
        config = json.loads(path.read_text())['netwatcher']
        config = replace_data(config, sensor_state if kind == 'sensor' else console_state)
        config['native']['control'].update(socket_path=runtime+'/sensor.sock', allowed_uid=console.pw_uid,
            socket_gid=console.pw_gid, expected_uid=sensor.pw_uid)
        config['postgresql'].update(host=database['NETWATCHER_DB_HOST'], port=int(database['NETWATCHER_DB_PORT']),
            database=database['NETWATCHER_DB_NAME'], search_path=schema+',public')
        state = sensor_state if kind == 'sensor' else console_state
        config['logging']['directory'] = state + '/logs'
        if kind == 'sensor':
            config['threatfeeds']['config_path'] = sensor_state + '/threatfeeds.yaml'
        else:
            config['web']['host'] = '127.0.0.1'
        path.write_text(json.dumps({'netwatcher': config}, ensure_ascii=False, indent=2)+'\n')
    (output/'config/default.yaml').write_text((output/'config/console.yaml').read_text())
    for kind in ('console', 'sensor', 'migrate', 'bootstrap', 'grants'):
        path = output / (kind + '.env')
        values = dict(dotenv_values(path, interpolate=False))
        values.update({key: value for key, value in database.items() if key not in ('NETWATCHER_DB_USER', 'NETWATCHER_DB_PASSWORD')})
        values['NETWATCHER_DB_SEARCH_PATH'] = schema + ',public'
        if kind == 'bootstrap':
            values.update(database)
        write_env(path, values)
    # Compose용 관리 계정 파일을 호스트 서비스 배포 산출물에 남기지 않는다.
    (output/'.env').unlink()
    units = output / 'systemd'
    units.mkdir(mode=0o755)
    units.chmod(0o755)
    python = source + '/.venv/bin/python'
    common = f'''NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077
MemoryHigh=384M
MemoryMax=512M
CPUQuota=100%
TasksMax=128
WorkingDirectory={source}
BindReadOnlyPaths={source} {destination}
'''
    def unit(kind, body, dependencies='', install=False):
        text = f'[Unit]\nDescription=Panopticon native {kind}\nAfter=network-online.target {dependencies}\nWants=network-online.target\n'
        if dependencies:
            text += 'Requires='+dependencies+'\n'
        text += '\n[Service]\n'+common+body
        if install:
            text += '\n[Install]\nWantedBy=multi-user.target\n'
        (units/(prefix+'-'+kind+'.service')).write_text(text)
    init = prefix+'-init.service'
    grants = prefix+'-grants.service'
    unit('init', f'''Type=oneshot
RemainAfterExit=true
User={sensor.pw_uid}
Group={console.pw_gid}
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX
RuntimeDirectory={prefix}
RuntimeDirectoryMode=0710
RuntimeDirectoryPreserve=yes
StateDirectory={prefix}-sensor
StateDirectoryMode=0700
ExecStart={python} -m netwatcher.services.native_install --runtime {runtime} --data {sensor_state} --source {destination}/config --socket-gid {console.pw_gid}
''')
    for kind, credential, dependencies in (
            ('roles', 'bootstrap', ''), ('migrate', 'migrate', prefix+'-roles.service'),
            ('grants', 'grants', prefix+'-migrate.service')):
        unit(kind, f'''Type=oneshot
RemainAfterExit=true
User=0
Group=0
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LoadCredential=runtime.env:{destination}/{credential}.env
ExecStart={python} -m netwatcher.services.runtime_entrypoint {kind}
''', dependencies)
    for kind, user, state in (('sensor', sensor, sensor_state), ('console', console, console_state)):
        capabilities = 'CAP_NET_RAW' if kind == 'sensor' else ''
        config = sensor_state+'/sensor.yaml' if kind == 'sensor' else destination+'/config/console.yaml'
        body = f'''Type=simple
User={user.pw_uid}
Group={console.pw_gid}
CapabilityBoundingSet={capabilities}
AmbientCapabilities={capabilities}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6{' AF_PACKET AF_NETLINK' if kind=='sensor' else ''}
StateDirectory={prefix}-{kind}
StateDirectoryMode=0700
Environment=NETWATCHER_LOG_DIR={state}/logs XDG_CONFIG_HOME={state}/config XDG_CACHE_HOME={state}/cache
LoadCredential=runtime.env:{destination}/{kind}.env
ExecStart={python} -m netwatcher.services.runtime_entrypoint {kind} --config {config}
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
'''
        if kind == 'sensor':
            body += f'RuntimeDirectory={prefix}\nRuntimeDirectoryMode=0710\nRuntimeDirectoryPreserve=yes\n'
        else:
            body += f'BindReadOnlyPaths={runtime}\nInaccessiblePaths={sensor_state}\n'
        unit(kind, body, init+' '+grants, True)
    for path in units.iterdir():
        path.chmod(0o644)
    return output


def main():
    parser = argparse.ArgumentParser(description='분리 센서·콘솔의 systemd 설치 파일을 생성합니다.')
    parser.add_argument('--interface', required=True)
    parser.add_argument('--database-env', required=True)
    parser.add_argument('--console-user', required=True)
    parser.add_argument('--sensor-user', required=True)
    parser.add_argument('--output', default='installation-native-systemd')
    parser.add_argument('--source', default='/opt/panopticon')
    parser.add_argument('--destination', default='/etc/panopticon-native')
    parser.add_argument('--prefix', default='panopticon-native')
    parser.add_argument('--schema', default='netwatcher')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--sensor-id', default='office-native')
    args = parser.parse_args()
    try:
        output = prepare_systemd_installation(**vars(args))
    except (ValueError, OSError) as exc:
        parser.exit(1, '설정 생성 실패: '+(str(exc) if isinstance(exc, ValueError) else type(exc).__name__)+'\n')
    print(f'서비스와 설정 생성 완료: {output}')
    print(f'로그인 정보 파일: {output / "console.env"}')


if __name__ == '__main__':
    main()
