"""관리형 설치의 GitHub 정식 릴리스를 검증하고 적용한다."""
from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

REPOSITORY = 'JinHo-von-Choi/panopticon'
API = 'https://api.github.com/repos/' + REPOSITORY
MAX_METADATA = 2 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
FALSE_VALUES = {'0', 'false', 'no', 'off'}


def enabled(environ=None):
    value = (os.environ if environ is None else environ).get('PANOPTICON_AUTO_UPDATE', 'true').strip().lower()
    if value in FALSE_VALUES:
        return False
    if value not in {'1', 'true', 'yes', 'on'}:
        raise ValueError('PANOPTICON_AUTO_UPDATE must be true or false')
    return True


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise ValueError('Invalid stable version')
    return tuple(map(int, value.removeprefix('v').split('.')))


def source_version(directory):
    tree = ast.parse((directory / 'netwatcher/__init__.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '__version__' for t in node.targets):
            value = ast.literal_eval(node.value)
            version(value)
            return value
    raise ValueError('Missing application version')


def run(command, *, cwd=None, env=None, stdin=None, stdout=None):
    # Command output may contain credentials; journal receives only our status messages.
    completed = subprocess.run(command, cwd=cwd, env=env, stdin=stdin, stdout=stdout or subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=1800, check=False)
    if completed.returncode:
        raise RuntimeError('Update command failed: ' + Path(command[0]).name)


class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        from urllib.parse import urlsplit
        parsed = urlsplit(newurl)
        if parsed.scheme != 'https' or parsed.hostname not in {
                'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}:
            raise ValueError('Unexpected release redirect')
        return super().redirect_request(request, fp, code, message, headers, newurl)


def fetch(url, destination=None, limit=MAX_METADATA):
    request = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json',
                                                   'User-Agent': 'Panopticon-Updater'})
    # Deliberately ignore host proxy settings for release downloads.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ReleaseRedirect())
    with opener.open(request, timeout=30) as response:
        if response.geturl().split('/')[2] not in {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}:
            raise ValueError('Unexpected release download host')
        payload = bytearray()
        stream = destination.open('xb') if destination else None
        try:
            total = 0
            while chunk := response.read(65536):
                total += len(chunk)
                if total > limit:
                    raise ValueError('Release asset exceeds size limit')
                if stream:
                    stream.write(chunk)
                else:
                    payload.extend(chunk)
            return bytes(payload)
        finally:
            if stream:
                stream.close()


def latest_release():
    try:
        release = json.loads(fetch(API + '/releases/latest'))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    if not isinstance(release, dict) or release.get('draft') is not False or release.get('prerelease') is not False:
        raise ValueError('Not a published stable release')
    version(release.get('tag_name'))
    return release


def verify_download(release, directory, gh):
    tag = release['tag_name']
    number = tag.removeprefix('v')
    names = [f'panopticon-{number}.tar.gz', 'release.json', 'SHA256SUMS', 'provenance.sigstore.json']
    assets = release.get('assets', [])
    if not isinstance(assets, list):
        raise ValueError('Invalid release assets')
    indexed = {}
    for asset in assets:
        if isinstance(asset, dict) and asset.get('name') in names:
            if asset['name'] in indexed:
                raise ValueError('Duplicate release asset')
            indexed[asset['name']] = asset
    for name in names:
        asset = indexed.get(name)
        expected = 'https://github.com/' + REPOSITORY + '/releases/download/' + tag + '/' + name
        if asset is None or asset.get('browser_download_url') != expected or asset.get('state') != 'uploaded':
            raise ValueError('Missing verified release assets')
        fetch(expected, directory / name, MAX_ARCHIVE if name.endswith('.tar.gz') else MAX_METADATA)
    manifest = json.loads((directory / 'release.json').read_text())
    if manifest.get('tag') != tag or manifest.get('version') != number or not re.fullmatch(r'[0-9a-f]{40}', manifest.get('source_commit', '')):
        raise ValueError('Release manifest mismatch')
    # Pin repository, workflow, commit and tag; checksum alone is not a trust anchor.
    for name in names[:3]:
        run([gh, 'attestation', 'verify', str(directory / name), '--bundle', str(directory / names[3]),
             '--repo', REPOSITORY, '--signer-workflow', REPOSITORY + '/.github/workflows/release.yml',
             '--source-digest', manifest['source_commit'], '--source-ref', 'refs/tags/' + tag])
    checksums = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        if match is None or match[2] in checksums:
            raise ValueError('Invalid checksum manifest')
        checksums[match[2]] = match[1]
    for name in names[:2]:
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        if checksums.get(name) != digest:
            raise ValueError('Release checksum mismatch')
    if manifest.get('source_archive_sha256') != checksums[names[0]]:
        raise ValueError('Source archive mismatch')
    return directory / names[0], manifest


def unpack(archive, target, number):
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    total, seen = 0, set()
    with tarfile.open(archive, 'r:gz') as source:
        for item in source:
            path = PurePosixPath(item.name)
            if (path.is_absolute() or '..' in path.parts or not path.parts or
                    path.parts[0] != 'panopticon-' + number or not (item.isfile() or item.isdir())):
                raise ValueError('Unsafe archive member')
            relative = Path(*path.parts[1:])
            if not relative.parts:
                continue
            if relative in seen:
                raise ValueError('Duplicate archive member')
            seen.add(relative)
            total += item.size
            if total > MAX_ARCHIVE or len(seen) > 10000:
                raise ValueError('Expanded archive exceeds limit')
            destination = target / relative
            if item.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(item) as stream, destination.open('xb') as output:
                    shutil.copyfileobj(stream, output)
                destination.chmod(0o755 if item.mode & 0o111 else 0o644)
    for path in target.rglob('*'):
        if path.is_dir():
            path.chmod(0o755)
    if source_version(target) != number:
        raise ValueError('Archive version mismatch')


def safe_file(path, *, private=False):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ValueError('Updater files must be owned by the updater and not writable by others')
    if private and info.st_mode & 0o077:
        raise ValueError('Credential files must be readable only by the updater')
    # Also protect every parent: an application user must not replace the manifest/credentials.
    for parent in path.parents:
        info = parent.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Updater parent directory is not protected')


def read_env(path):
    safe_file(path, private=True)
    if path.stat().st_size > 65536:
        raise ValueError('Environment file too large')
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
        if match is None:
            raise ValueError('Invalid environment file')
        value = match[2]
        if value[:1] in {'"', "'"}:
            if value[-1:] != value[:1]:
                raise ValueError('Invalid quoted environment value')
            value = re.sub(r'\\([\\\'\"])', r'\1', value[1:-1])
        elif any(c in value for c in '$`\r\n\x00'):
            raise ValueError('Environment expansion is not supported')
        values[match[1]] = value
    return values


def activate(link, destination):
    # Unique directories prevent an interrupted previous swap from blocking recovery.
    with tempfile.TemporaryDirectory(prefix='.panopticon-update-', dir=link.parent) as directory:
        temporary = Path(directory) / 'source'
        temporary.symlink_to(destination, target_is_directory=True)
        os.replace(temporary, link)
        descriptor = os.open(link.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class Installation:
    def __init__(self, config):
        self.config = config
        self.current = Path(config['source'])
        self.state = Path(config['state'])
        self.mode = config['mode']
        self.env = dict(os.environ)
        self.env.update(read_env(Path(config['env_file'])))
        self.env['NETWATCHER_SKIP_DOTENV'] = '1'
        db = read_env(Path(config.get('database_env', config['env_file'])))
        self.db = dict(self.env)
        self.db.update(db)
        for suffix, key in [('HOST', 'PGHOST'), ('PORT', 'PGPORT'), ('NAME', 'PGDATABASE'), ('USER', 'PGUSER'), ('PASSWORD', 'PGPASSWORD')]:
            self.db[key] = db.get('NETWATCHER_DB_' + suffix, '')
        if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', self.db[key]) for key in ('PGDATABASE', 'PGUSER')):
            raise ValueError('Use a dedicated database and a backup account with simple identifiers')
        if self.db['PGDATABASE'] in {'postgres', 'template0', 'template1'}:
            raise ValueError('System databases cannot be managed')
        self.services = config.get('services', [])
        if self.mode not in {'compose-eve', 'compose-native', 'systemd-eve', 'systemd-native'}:
            raise ValueError('Unsupported installation mode')
        if self.mode.startswith('systemd') and (not self.services or any(not re.fullmatch(r'panopticon[a-z0-9-]*\.service', s) for s in self.services)):
            raise ValueError('Invalid managed systemd services')
        if not self.current.is_symlink() or self.current.resolve().parent != self.state / 'releases':
            raise ValueError('Use install_auto_update.py to register a managed source directory')
        if self.mode.startswith('compose') and not self.env.get('COMPOSE_PROJECT_NAME'):
            raise ValueError('A fixed Compose project name is required to preserve volumes')

    def compose(self, source):
        command = ['docker', 'compose', '--project-directory', str(source), '--env-file', self.config['env_file'], '-f', str(source / 'docker-compose.yml')]
        if self.mode == 'compose-native':
            command += ['-f', str(source / 'docker-compose.native.yml')]
        if self.config.get('local_database', True):
            command += ['--profile', 'db']
        identity = hashlib.sha256(str(source).encode()).hexdigest()[:16]
        overrides = self.state / 'compose'
        overrides.mkdir(mode=0o700, exist_ok=True)
        path = overrides / (identity + '.json')
        targets = {'netwatcher': 'eve', 'db-migrate': 'eve'} if self.mode == 'compose-eve' else {
            'netwatcher': 'native-console', 'native-sensor': 'native', 'native-init': 'native',
            'db-migrate': 'native-console', 'native-db-roles': 'native-console', 'native-db-grants': 'native-console'}
        path.write_text(json.dumps({'services': {name: {'image': 'panopticon-managed-' + target + ':' + identity}
                                                for name, target in targets.items()}}) + '\n')
        return command + ['-f', str(path)]

    def prepare(self, source):
        if self.mode.startswith('compose'):
            run(self.compose(source) + ['build'], env=self.env)
        else:
            python = str(self.current / '.venv/bin/python')
            run([python, '-m', 'venv', str(source / '.venv')])
            run([str(source / '.venv/bin/python'), '-m', 'pip', 'install', '--require-hashes', '-r', str(source / 'requirements.lock')])

    def stop(self, source):
        if self.mode.startswith('compose'):
            run(self.compose(source) + ['stop', 'netwatcher'] + (['native-sensor'] if self.mode == 'compose-native' else []), env=self.env)
        else:
            run(['systemctl', 'stop', *self.services])

    def database_command(self, source, command):
        if self.mode.startswith('compose') and self.config.get('local_database', True):
            return self.compose(source) + ['exec', '-T', 'db', *command]
        return command

    def validate_recovery(self, source):
        query = 'SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname=current_user'
        with tempfile.TemporaryFile() as output:
            run(self.database_command(source, ['psql', '-U', self.db['PGUSER'], '-d', self.db['PGDATABASE'],
                 '-At', '-v', 'ON_ERROR_STOP=1', '-c', query]), env=self.db, stdout=output)
            output.seek(0)
            if output.read(32).strip() != b't':
                raise ValueError('Backup account needs database recreation privileges for recovery')

    def backup(self, source, path):
        with path.open('xb') as output:
            run(self.database_command(source, ['pg_dump', '-U', self.db['PGUSER'], '-d', self.db['PGDATABASE'], '-Fc']), env=self.db, stdout=output)
            output.flush()
            os.fsync(output.fileno())
        if path.stat().st_size < 32:
            raise ValueError('Database backup is empty')

    def restore(self, source, backup):
        # Dedicated DB only. Explicitly remove new-schema objects before restoring the snapshot.
        for command in [ ['dropdb', '-U', self.db['PGUSER'], '--force', self.db['PGDATABASE']],
                         ['createdb', '-U', self.db['PGUSER'], '-O', self.db['PGUSER'], self.db['PGDATABASE']] ]:
            run(self.database_command(source, command), env=self.db)
        with backup.open('rb') as stream:
            run(self.database_command(source, ['pg_restore', '-U', self.db['PGUSER'], '-d', self.db['PGDATABASE'], '--exit-on-error']), env=self.db, stdin=stream)

    def migrate(self, source):
        if self.mode.startswith('compose'):
            if self.mode == 'compose-native':
                run(self.compose(source) + ['run', '--rm', '--no-deps', 'native-db-roles'], env=self.env)
            run(self.compose(source) + ['--profile', 'migrate', 'run', '--rm', '--no-deps', 'db-migrate'], env=self.env)
            if self.mode == 'compose-native':
                run(self.compose(source) + ['run', '--rm', '--no-deps', 'native-db-grants'], env=self.env)
        else:
            migration_env = dict(self.env)
            migration_env.update(read_env(Path(self.config.get('migration_env', self.config['database_env']))))
            if self.config.get('application_config'):
                migration_env['NETWATCHER_CONFIG'] = self.config['application_config']
            run([str(source / '.venv/bin/python'), '-m', 'alembic', '-c', str(source / 'alembic.ini'), 'upgrade', 'head'], cwd=source, env=migration_env)
            if self.mode == 'systemd-native':
                grants_env = dict(self.env) | read_env(Path(self.config['grants_env']))
                run([str(source / '.venv/bin/python'), '-m', 'netwatcher.storage.runtime_roles', 'grants'], cwd=source, env=grants_env)

    def start(self, source):
        if self.mode.startswith('compose'):
            run(self.compose(source) + ['up', '-d', '--no-build', 'netwatcher'] + (['native-sensor'] if self.mode == 'compose-native' else []), env=self.env)
        else:
            run(['systemctl', 'start', *self.services])

    def healthy(self):
        url = self.config.get('health_url', 'http://127.0.0.1:38585/health')
        if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}/health', url):
            raise ValueError('Health probe must use the local console')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        last_error = 'No successful probe'
        for _ in range(60):
            try:
                with opener.open(url, timeout=2) as response:
                    payload = json.loads(response.read(4096))
                    expected = source_version(self.current)
                    if response.status == 200 and payload.get('status') == 'healthy' and (payload.get('version') == expected or (version(expected) < (0, 5, 0) and 'version' not in payload)):
                        if self.mode.startswith('systemd'):
                            run(['systemctl', 'is-active', '--quiet', *self.services])
                        else:
                            services = ['netwatcher'] + (['native-sensor'] if self.mode == 'compose-native' else [])
                            for service in services:
                                run(self.compose(self.current) + ['exec', '-T', service, 'python', '-c', 'import netwatcher; assert netwatcher.__version__ == ' + repr(expected)], env=self.env)
                        return
            except (OSError, urllib.error.URLError, ValueError, RuntimeError) as error:
                last_error = type(error).__name__
            time.sleep(2)
        raise RuntimeError('Updated console did not become healthy: ' + last_error)


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.next')
    with temporary.open('w') as stream:
        json.dump(value, stream)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_status(state, status, **fields):
    atomic_json(state / 'status.json', {'status': status, 'checked_at': int(time.time()), **fields})


def update(installation, release, gh):
    state = installation.state
    old = installation.current.resolve()
    installation.validate_recovery(old)
    number = release['tag_name'].removeprefix('v')
    destination = state / 'releases' / (number + '-' + str(time.time_ns()))
    backup = state / 'backups' / (number + '-' + str(time.time_ns()) + '.dump')
    with tempfile.TemporaryDirectory(prefix='download-', dir=state) as temporary:
        archive, manifest = verify_download(release, Path(temporary), gh)
        unpack(archive, destination, number)
        if installation.mode.startswith('compose'):
            installation.prepare(old)
        installation.prepare(destination)
    write_status(state, 'prepared', version=number)
    # Write the recovery journal before stopping any component; interrupted updates recover on next run.
    journal = state / 'recovery.json'
    atomic_json(journal, {'old': str(old), 'new': str(destination), 'backup': str(backup), 'phase': 'stopping'})
    try:
        installation.stop(old)
        installation.backup(old, backup)
        atomic_json(journal, {'old': str(old), 'new': str(destination), 'backup': str(backup), 'phase': 'migrating'})
        installation.migrate(destination)
        activate(installation.current, destination)
        installation.start(destination)
        installation.healthy()
    except Exception:
        recover(installation)
        raise
    journal.unlink()
    write_status(state, 'updated', version=number, source_commit=manifest['source_commit'])


def recover(installation):
    journal = installation.state / 'recovery.json'
    if not journal.exists():
        return
    entry = json.loads(journal.read_text())
    old, new, backup = (Path(entry[k]) for k in ('old', 'new', 'backup'))
    if any(p.parent != installation.state / 'releases' for p in (old, new)) or backup.parent != installation.state / 'backups':
        raise ValueError('Invalid recovery journal paths')
    installation.stop(installation.current.resolve())
    if entry['phase'] == 'migrating':
        installation.restore(old, backup)
    activate(installation.current, old)
    installation.start(old)
    installation.healthy()
    journal.unlink()
    write_status(installation.state, 'rolled_back', version=source_version(old))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    safe_file(args.config)
    config = json.loads(args.config.read_text())
    state = Path(config['state'])
    safe_file(state / 'owner')
    with (state / 'update.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Another Panopticon updater is running; skipped')
            return
        # Policy file is re-read on every run; disabling requires no daemon restart.
        policy = read_env(Path(config['policy_file']))
        if not enabled(policy | dict(os.environ)):
            if (state / 'recovery.json').exists():
                recover(Installation(config))
            write_status(state, 'disabled')
            print('Panopticon automatic updates disabled')
            return
        try:
            installation = Installation(config)
            recover(installation)
            release = latest_release()
            if release is None or version(release['tag_name']) <= version(source_version(installation.current)):
                write_status(state, 'up_to_date', version=source_version(installation.current))
                print('Panopticon is up to date')
                return
            update(installation, release, config.get('gh', '/usr/bin/gh'))
            print('Panopticon updated to ' + release['tag_name'])
        except Exception as error:
            write_status(state, 'failed', error=type(error).__name__)
            print('Panopticon update failed: ' + type(error).__name__, file=sys.stderr)
            raise SystemExit(1) from None


if __name__ == '__main__':
    main()
