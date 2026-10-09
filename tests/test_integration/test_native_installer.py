"""직접 캡처 설치 설정·Compose 경계와 실제 볼륨 초기화를 검증한다."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from uuid import uuid4

from dotenv import dotenv_values
import pytest

from scripts.install_native import prepare_native_installation


def test_native_installation_private_credentials_and_consistent_sensor_identity(tmp_path):
    path=prepare_native_installation(tmp_path/'installation','eth0',sensor_id='office-1')
    values=dotenv_values(path)
    assert stat.S_IMODE(path.stat().st_mode)==0o600
    assert stat.S_IMODE(path.parent.stat().st_mode)==0o700
    sensor=json.loads((path.parent/'config/sensor.yaml').read_text())['netwatcher']
    console=json.loads((path.parent/'config/console.yaml').read_text())['netwatcher']
    assert sensor['native']==console['native']
    assert sensor['input']['mode']==console['input']['mode']=='native'
    assert sensor['native']['control']['allowed_uid']==10001
    assert sensor['native']['control']['expected_uid']==0
    assert sensor['auth']['multi_user'] and console['auth']['multi_user']
    assert not sensor['response']['enabled'] and not sensor['response_execution']['enabled']
    runtime=dotenv_values(path.parent/'console.env')
    sensor_env=dotenv_values(path.parent/'sensor.env')
    migration=dotenv_values(path.parent/'migrate.env')
    assert len({runtime['NETWATCHER_DB_PASSWORD'],sensor_env['NETWATCHER_DB_PASSWORD'],migration['NETWATCHER_DB_PASSWORD'],values['NETWATCHER_DB_PASSWORD']})==4
    for kind in ('console','sensor','migrate','bootstrap','grants'):
        assert stat.S_IMODE((path.parent/(kind+'.env')).stat().st_mode)==0o600
    for key in ('NETWATCHER_DB_PASSWORD','NETWATCHER_LOGIN_PASSWORD','NETWATCHER_JWT_SECRET'):
        assert len(runtime[key])>=32
        assert runtime[key] not in json.dumps(sensor) and runtime[key] not in json.dumps(console)
    assert not any(key.startswith('PANOPTICON_DB_') for key in runtime)
    assert not any(key.endswith('_PASSWORD') and key!='NETWATCHER_DB_PASSWORD' for key in sensor_env)
    assert migration['NETWATCHER_DB_PASSWORD'] not in (path.parent/'console.env').read_text()
    with pytest.raises(ValueError):prepare_native_installation(path.parent,'eth0')
    assert dotenv_values(path)==values


@pytest.mark.parametrize('interface',['','a/b','eth0\nprivate','x'*65])
def test_bad_interface_creates_no_installation(tmp_path,interface):
    with pytest.raises(ValueError):prepare_native_installation(tmp_path/'new',interface)
    assert not (tmp_path/'new').exists()


def test_native_installer_cli_keeps_credentials_private(tmp_path):
    result=subprocess.run([sys.executable,'-I','scripts/install_native.py','--interface','eth0',
        '--output',str(tmp_path/'new')],capture_output=True,text=True,timeout=10)
    assert result.returncode==0
    for file in (tmp_path/'new').glob('*.env'):
        for key,value in dotenv_values(file).items():
            if key.endswith(('PASSWORD','SECRET')):assert value not in result.stdout+result.stderr


def compose_model(environment):
    env={key:value for key,value in os.environ.items() if not key.startswith(('NETWATCHER_','PANOPTICON_'))}
    result=subprocess.run(['docker','compose','--env-file',str(environment),'-f','docker-compose.yml',
        '-f','docker-compose.native.yml','--profile','db','config','--no-env-resolution','--format','json'],
        env=env,capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    return json.loads(result.stdout)


def test_real_compose_has_separate_console_sensor_and_private_data(tmp_path):
    environment=prepare_native_installation(tmp_path/"installation $ literal 'quote",'eth0')
    model=compose_model(environment)
    console=model['services']['netwatcher'];sensor=model['services']['native-sensor'];init=model['services']['native-init']
    assert console['build']['target']=='native-console' and console['read_only']
    assert console['cap_drop']==['ALL'] and not console.get('cap_add') and console.get('network_mode')!='host'
    assert sensor['network_mode']=='host' and sensor['cap_drop']==['ALL'] and sensor['cap_add']==['NET_RAW']
    assert sensor['read_only'] and init['cap_add']==['CHOWN']
    assert console['command'][1]=='console' and sensor['command'][1]=='sensor'
    console_volumes={v['target']:v for v in console['volumes']}
    sensor_volumes={v['target']:v for v in sensor['volumes']}
    assert console_volumes['/app/data']['source']!=sensor_volumes['/app/data']['source']
    assert console_volumes['/run/panopticon']['read_only']
    assert console_volumes['/run/panopticon']['source']==sensor_volumes['/run/panopticon']['source']
    assert console_volumes['/app/config']['source']==str(environment.parent/'config').replace('$','$$')
    assert console['depends_on']['native-init']['condition']=='service_completed_successfully'


def test_real_container_initialization_keeps_mutated_sensor_config(tmp_path):
    image=os.environ.get('PANOPTICON_NATIVE_SENSOR_IMAGE')
    if not image or not shutil.which('docker'):pytest.skip('Provide current native image')
    environment=prepare_native_installation(tmp_path/'installation','eth0')
    prefix='panopticon-init-'+uuid4().hex[:12];data=prefix+'-data';runtime=prefix+'-runtime'
    def docker(*args):
        result=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=30)
        assert result.returncode==0,result.stderr[-1500:]
        return result.stdout
    try:
        docker('volume','create',data);docker('volume','create',runtime)
        arguments=['run','--rm','--network','none','--read-only','--cap-drop','ALL','--cap-add','CHOWN',
            '--security-opt','no-new-privileges','--group-add','10001',
            '--mount',f'type=bind,src={environment.parent / "config"},dst=/app/config,readonly',
            '--mount',f'type=volume,src={data},dst=/app/data',
            '--mount',f'type=volume,src={runtime},dst=/run/panopticon','--entrypoint','python',image]
        docker(*arguments,'-m','netwatcher.services.native_install')
        code="""
from pathlib import Path
import json,stat
p=Path('/app/data/sensor.yaml');value=json.loads(p.read_text());value['netwatcher']['engines']['port_scan']['threshold']=37
p.write_text(json.dumps(value));info=Path('/run/panopticon').stat()
assert info.st_uid==0 and info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o710
assert stat.S_IMODE(p.stat().st_mode)==0o600
"""
        docker(*arguments,'-c',code)
        docker(*arguments,'-m','netwatcher.services.native_install')
        docker(*arguments,'-c',"import json;assert json.load(open('/app/data/sensor.yaml'))['netwatcher']['engines']['port_scan']['threshold']==37")
    finally:
        subprocess.run(['docker','volume','rm',data,runtime],capture_output=True,timeout=15)
