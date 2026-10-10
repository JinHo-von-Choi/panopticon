"""업데이트 정책, 신뢰 경계, 실제 파일 전환과 실패 복구를 확인한다."""
import io
import json
from pathlib import Path
import tarfile
import urllib.error

import pytest

from scripts import auto_update as updater
from scripts.install_auto_update import timer_units


@pytest.mark.parametrize('value', ['false', '0', 'off', 'NO', ' false '])
def test_disable_switch(value):
    assert not updater.enabled({'PANOPTICON_AUTO_UPDATE': value})


def test_default_enabled_and_invalid_value_rejected():
    assert updater.enabled({})
    with pytest.raises(ValueError):
        updater.enabled({'PANOPTICON_AUTO_UPDATE': 'maybe'})


def test_semantic_version_prevents_lexicographic_downgrade():
    assert updater.version('v0.10.0') > updater.version('0.9.9')
    for value in ('v0.5.0-rc1', 'v0.5.0/../../x', '0.05.0', 'main', None):
        with pytest.raises(ValueError):
            updater.version(value)


def archive(path, members):
    with tarfile.open(path, 'w:gz') as stream:
        for name, contents, kind in members:
            item = tarfile.TarInfo(name)
            if kind == 'symlink':
                item.type = tarfile.SYMTYPE
                item.linkname = '/etc/passwd'
                stream.addfile(item)
            else:
                payload = contents.encode()
                item.size = len(payload)
                stream.addfile(item, io.BytesIO(payload))


def test_real_archive_extracts_and_has_readable_permissions(tmp_path):
    bundle = tmp_path / 'source.tar.gz'
    archive(bundle, [('panopticon-0.5.0/netwatcher/__init__.py', '__version__="0.5.0"', 'file')])
    output = tmp_path / 'new'
    updater.unpack(bundle, output, '0.5.0')
    assert updater.source_version(output) == '0.5.0'
    assert output.stat().st_mode & 0o777 == 0o755
    assert (output / 'netwatcher').stat().st_mode & 0o777 == 0o755
    assert (output / 'netwatcher/__init__.py').stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize('name,kind', [('panopticon-0.5.0/../../outside', 'file'),
    ('panopticon-0.5.0/link', 'symlink'), ('/absolute', 'file')])
def test_unsafe_archive_members_are_rejected(tmp_path, name, kind):
    bundle = tmp_path / 'unsafe.tar.gz'
    archive(bundle, [(name, 'x', kind)])
    with pytest.raises(ValueError, match='Unsafe'):
        updater.unpack(bundle, tmp_path / 'new', '0.5.0')
    assert not (tmp_path / 'outside').exists()


def test_release_404_means_no_release_but_other_errors_propagate(monkeypatch):
    def fail(url):
        raise urllib.error.HTTPError(url, 404, 'missing', {}, None)
    monkeypatch.setattr(updater, 'fetch', fail)
    assert updater.latest_release() is None
    def unavailable(url):
        raise urllib.error.HTTPError(url, 503, 'unavailable', {}, None)
    monkeypatch.setattr(updater, 'fetch', unavailable)
    with pytest.raises(urllib.error.HTTPError):
        updater.latest_release()


def test_drafts_and_prereleases_are_never_used(monkeypatch):
    for release in ({'draft': True, 'prerelease': False, 'tag_name': 'v0.5.0'},
                    {'draft': False, 'prerelease': True, 'tag_name': 'v0.5.0'}):
        monkeypatch.setattr(updater, 'fetch', lambda url: json.dumps(release).encode())
        with pytest.raises(ValueError):
            updater.latest_release()


def test_redirect_rejects_private_and_non_https_before_following():
    redirect = updater.ReleaseRedirect()
    for url in ('http://github.com/file', 'https://127.0.0.1/file', 'https://evil.invalid/file'):
        with pytest.raises(ValueError):
            redirect.redirect_request(None, None, 302, 'found', {}, url)


def test_missing_signed_assets_refuses_download(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, 'fetch', lambda *args: pytest.fail('Do not download incomplete releases'))
    with pytest.raises(ValueError, match='Missing'):
        updater.verify_download({'tag_name': 'v0.5.0', 'assets': []}, tmp_path, '/unused/gh')


def test_signature_rejection_precedes_extraction(monkeypatch, tmp_path):
    number = '0.5.0'
    names = [f'panopticon-{number}.tar.gz', 'release.json', 'SHA256SUMS', 'provenance.sigstore.json']
    release = {'tag_name': 'v' + number, 'assets': [ {'name': name, 'state': 'uploaded',
        'browser_download_url': 'https://github.com/' + updater.REPOSITORY + '/releases/download/v' + number + '/' + name} for name in names]}
    def download(url, destination, limit):
        payload = json.dumps({'tag': 'v0.5.0', 'version': number, 'source_commit': 'a' * 40}) if destination.name == 'release.json' else 'untrusted'
        destination.write_text(payload)
    monkeypatch.setattr(updater, 'fetch', download)
    def reject(command, **kwargs):
        assert '--source-ref' in command and 'refs/tags/v0.5.0' in command
        raise RuntimeError('bad signature')
    monkeypatch.setattr(updater, 'run', reject)
    with pytest.raises(RuntimeError, match='bad signature'):
        updater.verify_download(release, tmp_path, 'gh')
    assert not (tmp_path / 'netwatcher').exists()


class Installation:
    mode = 'systemd-eve'
    def __init__(self, path, fail=None):
        self.state = path
        (path / 'releases').mkdir()
        (path / 'backups').mkdir()
        old = path / 'releases/old'
        (old / 'netwatcher').mkdir(parents=True)
        (old / 'netwatcher/__init__.py').write_text('__version__="0.4.0"')
        self.current = path / 'current'
        self.current.symlink_to(old)
        self.calls, self.fail = [], fail
    def validate_recovery(self, source):
        pass
    def prepare(self, source):
        self.calls.append('prepare')
        if self.fail == 'prepare':
            raise RuntimeError('prepare')
    def stop(self, source):
        self.calls.append('stop')
    def backup(self, source, path):
        path.write_bytes(b'backup')
        self.calls.append('backup')
    def restore(self, source, backup):
        assert backup.read_bytes() == b'backup'
        self.calls.append('restore')
    def migrate(self, source):
        self.calls.append('migrate')
        if self.fail == 'migrate':
            raise RuntimeError('migrate')
    def start(self, source):
        self.calls.append('start:' + updater.source_version(source))
    def healthy(self):
        self.calls.append('health')
        if self.fail == 'health':
            self.fail = None
            raise RuntimeError('health')


@pytest.fixture
def prepared_release(tmp_path, monkeypatch):
    bundle = tmp_path / 'archive.tar.gz'
    archive(bundle, [('panopticon-0.5.0/netwatcher/__init__.py', '__version__="0.5.0"', 'file')])
    monkeypatch.setattr(updater, 'verify_download', lambda *args: (bundle, {'source_commit': 'a' * 40}))
    return {'tag_name': 'v0.5.0'}


def test_success_keeps_backup_and_switches_actual_source(tmp_path, prepared_release):
    install = Installation(tmp_path)
    updater.update(install, prepared_release, 'gh')
    assert updater.source_version(install.current) == '0.5.0'
    assert install.calls == ['prepare', 'stop', 'backup', 'migrate', 'start:0.5.0', 'health']
    assert not (tmp_path / 'recovery.json').exists()
    assert json.loads((tmp_path / 'status.json').read_text())['status'] == 'updated'
    assert len(list((tmp_path / 'backups').glob('*.dump'))) == 1


@pytest.mark.parametrize('failure', ['migrate', 'health'])
def test_failed_update_restores_old_source_and_database(tmp_path, prepared_release, failure):
    install = Installation(tmp_path, failure)
    with pytest.raises(RuntimeError):
        updater.update(install, prepared_release, 'gh')
    assert updater.source_version(install.current) == '0.4.0'
    assert 'restore' in install.calls and 'start:0.4.0' in install.calls
    assert json.loads((tmp_path / 'status.json').read_text())['status'] == 'rolled_back'


def test_prepare_failure_does_not_stop_live_service(tmp_path, prepared_release):
    install = Installation(tmp_path, 'prepare')
    with pytest.raises(RuntimeError):
        updater.update(install, prepared_release, 'gh')
    assert install.calls == ['prepare']
    assert updater.source_version(install.current) == '0.4.0'
    assert not (tmp_path / 'recovery.json').exists()


def test_interrupted_update_recovered_from_durable_journal(tmp_path):
    install = Installation(tmp_path)
    old = install.current.resolve()
    new = tmp_path / 'releases/new'
    (new / 'netwatcher').mkdir(parents=True)
    (new / 'netwatcher/__init__.py').write_text('__version__="0.5.0"')
    updater.activate(install.current, new)
    backup = tmp_path / 'backups/old.dump'
    backup.write_bytes(b'backup')
    updater.atomic_json(tmp_path / 'recovery.json', {'old': str(old), 'new': str(new), 'backup': str(backup), 'phase': 'migrating'})
    updater.recover(install)
    assert install.current.resolve() == old
    assert install.calls == ['stop', 'restore', 'start:0.4.0', 'health']


@pytest.mark.parametrize('policy_value,environment_value', [('false', None), ('true', 'false')])
def test_disable_prevents_network_and_service_commands(tmp_path, monkeypatch, policy_value, environment_value):
    config = tmp_path / 'installation.json'
    config.write_text(json.dumps({'state': str(tmp_path), 'policy_file': str(tmp_path / 'policy.env')}))
    monkeypatch.setattr(updater, 'safe_file', lambda path: None)
    monkeypatch.setattr(updater, 'read_env', lambda path: {'PANOPTICON_AUTO_UPDATE': policy_value})
    if environment_value is None:
        monkeypatch.delenv('PANOPTICON_AUTO_UPDATE', raising=False)
    else:
        monkeypatch.setenv('PANOPTICON_AUTO_UPDATE', environment_value)
    monkeypatch.setattr(updater, 'latest_release', lambda: pytest.fail('No network when disabled'))
    monkeypatch.setattr(updater, 'run', lambda *a, **k: pytest.fail('No service changes when disabled'))
    monkeypatch.setattr('sys.argv', ['update', '--config', str(config)])
    updater.main()
    assert json.loads((tmp_path / 'status.json').read_text())['status'] == 'disabled'


def test_timer_checks_on_first_activation_and_at_four():
    service, timer = timer_units('/etc/panopticon-update/auto_update.py', '/etc/panopticon-update/installation.json', '/usr/bin/python3')
    assert 'OnActiveSec=5s' in timer and 'OnCalendar=*-*-* 04:00:00' in timer
    assert 'Persistent=true' in timer and 'Type=oneshot' in service


def test_real_postgres_backup_restore_preserves_rows_owners_and_grants(tmp_path):
    import os
    import secrets
    import shutil
    import subprocess
    import time
    from uuid import uuid4
    docker = shutil.which('docker')
    if not docker or subprocess.run([docker, 'image', 'inspect', 'postgres:16-alpine'], capture_output=True).returncode:
        pytest.skip('Requires a local PostgreSQL16 Docker image')
    name = 'panopticon-update-test-' + uuid4().hex[:12]
    credentials = tmp_path / 'postgres.env'
    credentials.write_text('POSTGRES_PASSWORD=' + secrets.token_hex(24) + '\n')
    credentials.chmod(0o600)
    def command(*args, input=None):
        return subprocess.run([docker, 'exec', '-i', name, *args], input=input, capture_output=True, check=True).stdout
    subprocess.run([docker, 'run', '-d', '--name', name, '--label', 'panopticon.test=auto-update',
                    '--network', 'none', '--env-file', str(credentials), 'postgres:16-alpine'], capture_output=True, check=True)
    try:
        for _ in range(60):
            ready = subprocess.run([docker, 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        assert ready.returncode == 0, 'PostgreSQL did not become ready'
        command('createdb', '-U', 'postgres', 'update_fixture')
        command('psql', '-U', 'postgres', '-d', 'update_fixture', '-v', 'ON_ERROR_STOP=1', input=b'''
CREATE ROLE fixture_owner; CREATE ROLE fixture_reader;
CREATE SCHEMA fixture AUTHORIZATION fixture_owner;
CREATE TABLE fixture.evidence(id integer PRIMARY KEY, note text);
ALTER TABLE fixture.evidence OWNER TO fixture_owner;
INSERT INTO fixture.evidence VALUES(1,'preserve');
GRANT USAGE ON SCHEMA fixture TO fixture_reader;
GRANT SELECT ON fixture.evidence TO fixture_reader;
''')
        installation = updater.Installation.__new__(updater.Installation)
        installation.db = dict(os.environ)
        installation.db.update(PGUSER='postgres', PGDATABASE='update_fixture')
        installation.database_command = lambda source, args: [docker, 'exec', '-i', name, *args]
        installation.validate_recovery(tmp_path)
        backup = tmp_path / 'before.dump'
        installation.backup(tmp_path, backup)
        command('psql', '-U', 'postgres', '-d', 'update_fixture', '-v', 'ON_ERROR_STOP=1', input=b"DELETE FROM fixture.evidence; CREATE TABLE fixture.new_schema_only(id int);")
        installation.restore(tmp_path, backup)
        observed = command('psql', '-U', 'postgres', '-d', 'update_fixture', '-At', '-v', 'ON_ERROR_STOP=1', input=b'''
SELECT note FROM fixture.evidence WHERE id=1;
SELECT to_regclass('fixture.new_schema_only') IS NULL;
SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='fixture.evidence'::regclass;
SELECT has_table_privilege('fixture_reader','fixture.evidence','SELECT');
''').decode().splitlines()
        assert observed == ['preserve', 't', 'fixture_owner', 't']
    finally:
        subprocess.run([docker, 'rm', '-f', '-v', name], capture_output=True, check=True)


@pytest.mark.parametrize('mode', ['compose-eve', 'compose-native'])
def test_actual_compose_config_preserves_project_and_separates_image_versions(tmp_path, mode):
    import shutil
    import subprocess
    from dotenv import dotenv_values
    from scripts.install_eve import prepare_installation
    from scripts.install_native import prepare_native_installation
    if not shutil.which('docker'):
        pytest.skip('Requires Docker Compose')
    root = Path(__file__).resolve().parents[2]
    if mode == 'compose-native':
        env_file = prepare_native_installation(tmp_path / 'installation', 'lo')
    else:
        tmp_path.chmod(0o750)
        eve = tmp_path / 'eve.json'
        eve.write_bytes(b'')
        eve.chmod(0o644)
        env_file = prepare_installation(tmp_path / 'installation', eve)
    installation = updater.Installation.__new__(updater.Installation)
    installation.mode, installation.state = mode, tmp_path
    installation.config = {'env_file': str(env_file), 'local_database': True}
    installation.env = dict(dotenv_values(env_file))
    command = installation.compose(root)
    result = subprocess.run(command + ['config', '--format', 'json'], env=installation.env, capture_output=True, check=True)
    config = json.loads(result.stdout)
    assert config['name'] == installation.env['COMPOSE_PROJECT_NAME']
    console_image = config['services']['netwatcher']['image']
    assert console_image.startswith('panopticon-managed-')
    other = tmp_path / 'next-source'
    other.mkdir()
    for file in ('docker-compose.yml', 'docker-compose.native.yml'):
        shutil.copyfile(root / file, other / file)
    next_config = json.loads(subprocess.run(installation.compose(other) + ['config', '--format', 'json'], env=installation.env, capture_output=True, check=True).stdout)
    assert next_config['services']['netwatcher']['image'] != console_image
    assert next_config['name'] == config['name']
    assert set(next_config['volumes']) == set(config['volumes'])
    if mode == 'compose-native':
        assert config['services']['native-sensor']['image'] != console_image
        assert config['services']['native-sensor']['cap_add'] == ['NET_RAW']
        assert config['services']['netwatcher']['cap_drop'] == ['ALL']


def test_read_env_preserves_generated_secret_quotes_and_rejects_expansion(tmp_path, monkeypatch):
    from scripts.install_eve import dotenv_value
    monkeypatch.setattr(updater, 'safe_file', lambda *args, **kwargs: None)
    file = tmp_path / 'env'
    value = "quote'back\\slash\"dollar$"
    file.write_text('NETWATCHER_DB_PASSWORD=' + dotenv_value(value) + '\n')
    assert updater.read_env(file)['NETWATCHER_DB_PASSWORD'] == value
    file.write_text('NETWATCHER_DB_PASSWORD=$(command)\n')
    with pytest.raises(ValueError, match='expansion'):
        updater.read_env(file)


def test_unsafe_credentials_are_rejected(tmp_path):
    file = tmp_path / 'env'
    file.write_text('PANOPTICON_AUTO_UPDATE=false\n')
    file.chmod(0o666)
    with pytest.raises(ValueError):
        updater.read_env(file)
    link = tmp_path / 'link'
    link.symlink_to(file)
    with pytest.raises(ValueError):
        updater.read_env(link)


def test_interrupted_temporary_link_does_not_block_next_recovery(tmp_path):
    install = Installation(tmp_path)
    old = install.current.resolve()
    new = tmp_path / 'releases/new'
    new.mkdir()
    # The former implementation reused this name and failed before entering its cleanup block.
    stale = install.current.with_name(install.current.name + '.update-link')
    stale.symlink_to(new)
    (tmp_path / '.panopticon-update-interrupted').mkdir()
    backup = tmp_path / 'backups/old.dump'
    backup.write_bytes(b'backup')
    updater.atomic_json(tmp_path / 'recovery.json', {'old': str(old), 'new': str(new), 'backup': str(backup), 'phase': 'migrating'})
    updater.recover(install)
    assert install.current.resolve() == old
    assert install.calls == ['stop', 'restore', 'start:0.4.0', 'health']
    assert not (tmp_path / 'recovery.json').exists()


def test_actual_verifier_uses_generated_service_paths_with_protected_home(tmp_path):
    import os
    import shutil
    import subprocess

    image = os.environ.get('PANOPTICON_NATIVE_SENSOR_IMAGE')
    gh = os.environ.get('PANOPTICON_GH_VERIFIER') or shutil.which('gh')
    if not image or not gh or not shutil.which('docker'):
        pytest.skip('Provide an owned runtime image and attestation verifier')
    binary = tmp_path / 'gh'
    shutil.copyfile(gh, binary)
    binary.chmod(0o755)
    service, _ = timer_units('/tmp/updater.py', '/tmp/update-settings/installation.json', '/usr/bin/python3')
    environment = [line.removeprefix('Environment=') for line in service.splitlines() if line.startswith('Environment=')]
    command = ['docker', 'run', '--rm', '--user', '0', '--cap-drop=ALL', '--read-only',
               '--tmpfs', '/root:ro,mode=000', '--tmpfs', '/tmp:rw,mode=1777',
               '--mount', 'type=bind,source=' + str(binary) + ',target=/usr/local/bin/gh,readonly',
               '--entrypoint', '/usr/local/bin/gh']
    # No credentials or accessible home directory: use the unit's generated paths.
    for value in environment:
        command.extend(['--env', value])
    result = subprocess.run(command + [image, 'attestation', 'trusted-root', '--verify-only'],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr[-1500:]


def test_real_postgres_schema_scope_restores_only_managed_schema(tmp_path):
    """공유 DB, 슈퍼유저 아닌 백업 계정: 관리 스키마만 되돌리고 다른 서비스 스키마는 건드리지 않는다."""
    import os
    import secrets
    import shutil
    import subprocess
    import time
    from uuid import uuid4
    docker = shutil.which('docker')
    if not docker or subprocess.run([docker, 'image', 'inspect', 'postgres:16-alpine'], capture_output=True).returncode:
        pytest.skip('Requires a local PostgreSQL16 Docker image')
    name = 'panopticon-update-test-' + uuid4().hex[:12]
    credentials = tmp_path / 'postgres.env'
    credentials.write_text('POSTGRES_PASSWORD=' + secrets.token_hex(24) + '\n')
    credentials.chmod(0o600)
    def command(*args, input=None, user='postgres'):
        return subprocess.run([docker, 'exec', '-i', name, *args], input=input, capture_output=True, check=True).stdout
    subprocess.run([docker, 'run', '-d', '--name', name, '--label', 'panopticon.test=auto-update',
                    '--network', 'none', '--env-file', str(credentials), 'postgres:16-alpine'], capture_output=True, check=True)
    try:
        for _ in range(60):
            ready = subprocess.run([docker, 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        assert ready.returncode == 0, 'PostgreSQL did not become ready'
        command('createdb', '-U', 'postgres', 'shared_fixture')
        command('psql', '-U', 'postgres', '-d', 'shared_fixture', '-v', 'ON_ERROR_STOP=1', input=b'''
CREATE ROLE app_admin LOGIN CREATEROLE; CREATE ROLE app_migrate; CREATE ROLE app_reader;
GRANT app_migrate TO app_admin WITH ADMIN OPTION, SET TRUE;
GRANT CREATE ON DATABASE shared_fixture TO app_admin;
CREATE SCHEMA app AUTHORIZATION app_admin;
GRANT ALL ON SCHEMA app TO app_migrate;
GRANT USAGE ON SCHEMA app TO app_reader;
SET ROLE app_migrate;
CREATE TABLE app.evidence(id integer PRIMARY KEY, note text);
CREATE FUNCTION app.marker() RETURNS int LANGUAGE sql AS 'SELECT 1';
INSERT INTO app.evidence VALUES(1,'preserve');
GRANT SELECT ON app.evidence TO app_reader;
RESET ROLE;
CREATE SCHEMA other_service;
CREATE TABLE other_service.data(id integer);
INSERT INTO other_service.data VALUES(1);
''')
        installation = updater.Installation.__new__(updater.Installation)
        installation.db = dict(os.environ)
        installation.db.update(PGUSER='app_admin', PGDATABASE='shared_fixture')
        installation.scope, installation.schema = 'schema', 'app'
        executed = []
        def database_command(source, args):
            # 호스트 파일 인자는 컨테이너로 복사해 같은 경로 이름으로 넘긴다.
            mapped = []
            for arg in args:
                if os.path.isfile(arg):
                    inside = '/tmp/' + uuid4().hex
                    subprocess.run([docker, 'cp', arg, name + ':' + inside], capture_output=True, check=True)
                    arg = inside
                mapped.append(arg)
            executed.append(args[0])
            return [docker, 'exec', '-i', name, *mapped]
        installation.database_command = database_command
        installation.validate_recovery(tmp_path)
        backup = tmp_path / 'before.dump'
        installation.backup(tmp_path, backup)
        command('psql', '-U', 'postgres', '-d', 'shared_fixture', '-v', 'ON_ERROR_STOP=1',
                input=b"DELETE FROM app.evidence; CREATE TABLE app.new_only(id int); INSERT INTO other_service.data VALUES(2);")
        installation.restore(tmp_path, backup)
        observed = command('psql', '-U', 'postgres', '-d', 'shared_fixture', '-At', '-v', 'ON_ERROR_STOP=1', input=b'''
SELECT note FROM app.evidence WHERE id=1;
SELECT to_regclass('app.new_only') IS NULL;
SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='app.evidence'::regclass;
SELECT pg_get_userbyid(proowner) FROM pg_proc WHERE proname='marker';
SELECT has_table_privilege('app_reader','app.evidence','SELECT');
SELECT has_schema_privilege('app_migrate','app','CREATE');
SELECT count(*) FROM other_service.data;
''').decode().splitlines()
        assert observed == ['preserve', 't', 'app_migrate', 'app_migrate', 't', 't', '2']
        assert 'dropdb' not in executed and 'createdb' not in executed
    finally:
        subprocess.run([docker, 'rm', '-f', '-v', name], capture_output=True, check=True)


def test_schema_scope_rejects_public_and_missing_schema(monkeypatch):
    monkeypatch.setattr(updater, 'read_env', lambda path: {'NETWATCHER_DB_NAME': 'shared', 'NETWATCHER_DB_USER': 'admin'})
    base = {'source': '/opt/panopticon', 'state': '/var/lib/panopticon-updater', 'mode': 'systemd-eve',
            'env_file': '/dev/null', 'services': ['panopticon-eve.service']}
    # 유효한 범위는 스키마 검사를 통과하고 그 다음의 소스 디렉터리 검사에서 멈춘다.
    for valid in ({'database_scope': 'schema', 'schema': 'netwatcher'}, {}):
        with pytest.raises(ValueError, match='managed source directory'):
            updater.Installation(base | valid)
    for schema in (None, 'public', 'pg_catalog', 'Bad-Name'):
        with pytest.raises(ValueError, match='managed application schema'):
            updater.Installation(base | {'database_scope': 'schema', 'schema': schema})
    with pytest.raises(ValueError, match='database_scope'):
        updater.Installation(base | {'database_scope': 'cluster'})


def test_prepared_release_is_readable_but_not_writable_by_service_users(tmp_path):
    """umask 077로 만든 venv도 서비스 계정이 실행할 수 있어야 한다."""
    import os
    import stat
    old = os.umask(0o077)
    try:
        venv = tmp_path / 'release' / '.venv' / 'bin'
        venv.mkdir(parents=True)
        python = venv / 'python'
        python.write_text('#!/bin/sh\n')
        python.chmod(0o700)
        data = tmp_path / 'release' / 'netwatcher.py'
        data.write_text('x = 1\n')
        (tmp_path / 'release' / 'shared').mkdir(mode=0o777)
    finally:
        os.umask(old)
    updater.make_readable(tmp_path / 'release')
    for path, expected in ((venv, 0o755), (python, 0o755), (data, 0o644), (tmp_path / 'release' / 'shared', 0o755)):
        assert stat.S_IMODE(path.stat().st_mode) == expected, path
