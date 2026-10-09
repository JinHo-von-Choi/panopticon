"""서비스 생성·자격증명 분리와 systemd의 실제 구문 검증."""

import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

from dotenv import dotenv_values
import pytest

from scripts.install_native_systemd import prepare_systemd_installation
from netwatcher.services.runtime_entrypoint import load_credentials


def database_file(tmp_path):
    path=tmp_path/'database.env'
    path.write_text("NETWATCHER_DB_HOST='127.0.0.1'\nNETWATCHER_DB_PORT='5432'\nNETWATCHER_DB_NAME='test'\nNETWATCHER_DB_USER='bootstrap'\nNETWATCHER_DB_PASSWORD='private-test-value'\n")
    path.chmod(0o600)
    return path


def users():
    console=pwd.getpwuid(os.getuid())
    sensor=pwd.getpwnam('nobody')
    assert console.pw_uid and console.pw_uid!=sensor.pw_uid
    return console,sensor


def test_generate_and_verify_units_with_separate_users_and_credentials(tmp_path):
    console,sensor=users()
    source=tmp_path/'source'
    (source/'.venv/bin').mkdir(parents=True)
    (source/'.venv/bin/python').symlink_to(sys.executable)
    output=tmp_path/'installation'
    result=prepare_systemd_installation(output,'lo',database_env=database_file(tmp_path),
        console_user=console.pw_name,sensor_user=sensor.pw_name,source=source,destination=output,
        prefix='panopticon-systemd-test')
    units=list((result/'systemd').glob('*.service'))
    assert len(units)==6
    verified=subprocess.run(['systemd-analyze','verify',*map(str,units)],capture_output=True,text=True,timeout=15)
    assert verified.returncode==0,verified.stderr
    config=json.loads((result/'config/sensor.yaml').read_text())['netwatcher']
    assert config['native']['control']['expected_uid']==sensor.pw_uid
    assert config['native']['control']['allowed_uid']==console.pw_uid
    assert config['evidence']['directory']=='/var/lib/panopticon-systemd-test-sensor/pcaps'
    all_units='\n'.join(path.read_text() for path in units)
    for kind in ('console','sensor','migrate','bootstrap','grants'):
        env=result/(kind+'.env')
        assert env.stat().st_mode & 0o777==0o600
        for key,value in dotenv_values(env).items():
            if key.endswith(('PASSWORD','SECRET')):
                assert value not in all_units
    assert not (result/'.env').exists()
    sensor_unit=(result/'systemd/panopticon-systemd-test-sensor.service').read_text()
    console_unit=(result/'systemd/panopticon-systemd-test-console.service').read_text()
    assert f'User={sensor.pw_uid}\n' in sensor_unit and 'AmbientCapabilities=CAP_NET_RAW' in sensor_unit
    assert f'User={console.pw_uid}\n' in console_unit and 'AmbientCapabilities=\n' in console_unit
    assert 'EnvironmentFile=' not in all_units
    with pytest.raises(ValueError):
        prepare_systemd_installation(output,'lo',database_env=database_file(tmp_path),
            console_user=console.pw_name,sensor_user=sensor.pw_name)


def test_insecure_database_file_creates_no_installation(tmp_path):
    console,sensor=users();credential=database_file(tmp_path);credential.chmod(0o644)
    with pytest.raises(ValueError,match='소유자만'):
        prepare_systemd_installation(tmp_path/'installation','lo',database_env=credential,
            console_user=console.pw_name,sensor_user=sensor.pw_name)
    assert not (tmp_path/'installation').exists()


def test_credential_loader_preserves_literal_substitutions_and_rejects_other_variables(tmp_path):
    path=tmp_path/'runtime.env'
    path.write_text("NETWATCHER_DB_PASSWORD='${HOME} literal'\nNETWATCHER_SKIP_DOTENV='1'\n")
    assert load_credentials(tmp_path)['NETWATCHER_DB_PASSWORD']=='${HOME} literal'
    path.write_text('LD_PRELOAD=/tmp/unsafe\n')
    with pytest.raises(ValueError):load_credentials(tmp_path)
    path.write_text('NETWATCHER_DB_PASSWORD='+'x'*32768)
    with pytest.raises(ValueError):load_credentials(tmp_path)
