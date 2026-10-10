"""기존 설치를 첫 실행·매일 04시 자동 업데이트 대상으로 등록한다."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auto_update import read_env, safe_file, source_version


def path_value(value):
    path = Path(value)
    if not path.is_absolute() or not re.fullmatch(r'/[A-Za-z0-9_./-]+', str(path)) or '..' in path.parts:
        raise ValueError('Use an absolute path without spaces or traversal')
    return path


def timer_units(script, config, python):
    settings = Path(config).parent
    service = f'''[Unit]
Description=Panopticon verified automatic update
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
Environment=GH_CONFIG_DIR={settings}/gh
Environment=XDG_CACHE_HOME={settings}/cache
ExecStart={python} {script} --config {config}
TimeoutStartSec=2h
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
'''
    timer = '''[Unit]
Description=Panopticon update at startup and 04:00 local time

[Timer]
OnActiveSec=5s
OnCalendar=*-*-* 04:00:00
Persistent=true
AccuracySec=1s
Unit=panopticon-update.service

[Install]
WantedBy=timers.target
'''
    return service, timer


def register(args):
    if os.geteuid() != 0:
        raise ValueError('Register the host updater as root')
    source, state = path_value(args.source), path_value(args.state)
    env_file, db_file = path_value(args.env_file), path_value(args.database_env or args.env_file)
    config_dir = path_value(args.settings)
    for file in (env_file, db_file):
        safe_file(file)
        if file.is_relative_to(source):
            raise ValueError('Keep settings and credentials outside the versioned source directory')
    values = read_env(env_file)
    if not source.is_dir() or source.is_symlink() or state.exists() or config_dir.exists():
        raise ValueError('Use an existing source directory and new updater directories')
    # A root updater must never execute source that another user can replace.
    for path in [source, *source.parents, *source.rglob('*')]:
        info = path.lstat()
        if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
            raise ValueError('Managed source must be root-owned and not writable by others')
        if path.is_symlink():
            target = path.resolve(strict=True)
            for referenced in (target, *target.parents):
                actual = referenced.stat()
                if actual.st_uid != 0 or actual.st_mode & 0o022:
                    raise ValueError('Managed source symlinks must have protected targets')
    number = source_version(source)
    if args.mode.startswith('compose') and not values.get('COMPOSE_PROJECT_NAME'):
        raise ValueError('Set COMPOSE_PROJECT_NAME to the existing project name')
    gh = path_value(args.gh)
    safe_file(gh.resolve())
    subprocess.run([str(gh), 'attestation', 'verify', '--help'], check=True, stdout=subprocess.DEVNULL)
    if args.mode.startswith('systemd'):
        if not args.services or any(not re.fullmatch(r'panopticon[a-z0-9-]*\.service', s) for s in args.services):
            raise ValueError('Specify the existing Panopticon service names')
        if not (source / '.venv/bin/python').exists():
            raise ValueError('Create the locked runtime .venv before registration')
    config = {'source': str(source), 'state': str(state), 'mode': args.mode,
              'env_file': str(env_file), 'database_env': str(db_file),
              'local_database': not args.external_database, 'services': args.services or [],
              'gh': str(gh), 'health_url': 'http://127.0.0.1:' + str(args.port) + '/health',
              'policy_file': str(config_dir / 'update.env'),
              'database_scope': args.database_scope}
    if args.database_scope == 'schema':
        if not args.schema:
            raise ValueError('Specify --schema with --database-scope schema')
        config['schema'] = args.schema
    if args.mode.startswith('systemd'):
        if not args.config:
            raise ValueError('Specify the existing external application configuration with --config')
        application_config = path_value(args.config)
        if application_config.is_relative_to(source) or not application_config.is_file():
            raise ValueError('Keep application configuration outside the managed source')
        config['application_config'] = str(application_config)
    if args.mode == 'systemd-native':
        config['migration_env'] = str(path_value(args.migration_env))
        config['grants_env'] = str(path_value(args.grants_env))
        for key in ('migration_env', 'grants_env'):
            safe_file(Path(config[key]))
            if Path(config[key]).is_relative_to(source):
                raise ValueError('Keep Native credentials outside the source directory')
    unit_dir = Path('/etc/systemd/system')
    for name in ('panopticon-update.service', 'panopticon-update.timer'):
        if (unit_dir / name).exists():
            raise ValueError('Updater service already exists')
    if source.parent.stat().st_dev != state.parent.stat().st_dev:
        raise ValueError('Source and updater state must use the same filesystem')
    for directory in (state.parent, config_dir.parent):
        for parent in (directory, *directory.parents):
            info = parent.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Updater directories must have protected parents')
    os.umask(0o077)
    state.mkdir(mode=0o755, parents=False)
    state.chmod(0o755)
    (state / 'releases').mkdir(mode=0o755)
    (state / 'releases').chmod(0o755)
    (state / 'backups').mkdir(mode=0o700)
    (state / 'owner').write_text('Panopticon managed updater\n')
    config_dir.mkdir(mode=0o700)
    (config_dir / 'gh').mkdir(mode=0o700)
    (config_dir / 'cache').mkdir(mode=0o700)
    initial = state / 'releases' / ('initial-' + number)
    # Same filesystem is required so enrollment can undo a failed rename without copying secrets.
    created_units = []
    moved = False
    try:
        script = config_dir / 'auto_update.py'
        shutil.copyfile(Path(__file__).with_name('auto_update.py'), script)
        script.chmod(0o600)
        manifest = config_dir / 'installation.json'
        manifest.write_text(json.dumps(config, indent=2) + '\n')
        (config_dir / 'update.env').write_text('PANOPTICON_AUTO_UPDATE=true\n')
        service, timer = timer_units(script, manifest, '/usr/bin/python3')
        for name, content in [('panopticon-update.service', service), ('panopticon-update.timer', timer)]:
            path = unit_dir / name
            with path.open('x') as stream:
                stream.write(content)
            created_units.append(path)
            path.chmod(0o644)
        source.rename(initial)
        moved = True
        source.symlink_to(initial, target_is_directory=True)
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', '--now', 'panopticon-update.timer'], check=True)
    except Exception:
        if created_units:
            subprocess.run(['systemctl', 'disable', '--now', 'panopticon-update.timer'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if moved:
            if source.is_symlink():
                source.unlink()
            initial.rename(source)
        for path in created_units:
            path.unlink()
        shutil.rmtree(config_dir)
        shutil.rmtree(state)
        subprocess.run(['systemctl', 'daemon-reload'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('compose-eve', 'compose-native', 'systemd-eve', 'systemd-native'), required=True)
    parser.add_argument('--source', default='/opt/panopticon')
    parser.add_argument('--state', default='/var/lib/panopticon-updater')
    parser.add_argument('--settings', default='/etc/panopticon-update')
    parser.add_argument('--env-file', required=True)
    parser.add_argument('--config')
    parser.add_argument('--database-env')
    parser.add_argument('--migration-env')
    parser.add_argument('--grants-env')
    parser.add_argument('--services', nargs='+')
    parser.add_argument('--external-database', action='store_true')
    parser.add_argument('--database-scope', choices=('database', 'schema'), default='database',
                        help='schema: back up and restore only --schema in a shared database')
    parser.add_argument('--schema')
    parser.add_argument('--port', type=int, default=38585)
    parser.add_argument('--gh', default='/usr/bin/gh')
    args = parser.parse_args()
    if not 0 < args.port < 65536:
        parser.error('Invalid console port')
    if args.mode == 'systemd-native' and not (args.migration_env and args.grants_env):
        parser.error('Native systemd requires migration and grants credential files')
    try:
        register(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Update registration failed: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__) + '\n')
    print('Automatic updates enabled: initial check and daily 04:00 local time')
    print('Disable: PANOPTICON_AUTO_UPDATE=false in ' + args.settings + '/update.env')


if __name__ == '__main__':
    main()
