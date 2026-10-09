"""고유 이름의 실제 systemd 서비스와 격리 DB 스키마를 사용한다."""

import asyncio
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import tempfile
from uuid import uuid4

from dotenv import dotenv_values
import httpx
import pytest

from scripts.install_eve import dotenv_value
from scripts.install_native_systemd import prepare_systemd_installation


@pytest.mark.asyncio
async def test_actual_systemd_native_services(db, config, tmp_path):
    if os.environ.get('PANOPTICON_SYSTEMD_TEST')!='1':
        pytest.skip('Explicit owned systemd test environment required')
    prefix='panopticon-sd-test-'+uuid4().hex[:12]
    schema='sd_'+uuid4().hex[:12]
    stage=Path(tempfile.mkdtemp(prefix=prefix+'-',dir='/var/tmp'))
    stage.chmod(0o755)
    source=stage/'source';source.mkdir(mode=0o755);source.chmod(0o755)
    repository=Path(__file__).resolve().parents[2]
    for name in ('netwatcher','config','alembic'):
        shutil.copytree(repository/name,source/name,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    shutil.copy2(repository/'alembic.ini',source/'alembic.ini')
    shutil.copytree('/tmp/panopticon-plan-py312',source/'.venv',symlinks=True)
    credential=stage/'database.env';pg=config.section('postgresql')
    credential.write_text('\n'.join(f'NETWATCHER_DB_{key}={dotenv_value(value)}' for key,value in {
        'HOST':pg['host'],'PORT':pg['port'],'NAME':pg['database'],'USER':pg['username'],'PASSWORD':pg['password']}.items())+'\n')
    credential.chmod(0o600)
    console=pwd.getpwuid(os.getuid());sensor=pwd.getpwnam('nobody')
    installation=prepare_systemd_installation(stage/'installation','lo',database_env=credential,
        console_user=console.pw_name,sensor_user=sensor.pw_name,source=source,destination=stage/'installation',
        prefix=prefix,schema=schema,sensor_id=prefix)
    installation.chmod(0o755)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
    for kind in ('console','sensor'):
        path=installation/'config'/(kind+'.yaml');value=json.loads(path.read_text())
        value['netwatcher'].setdefault('web',{})['port']=port
        if kind=='sensor':
            value['netwatcher']['promiscuous']=False
            value['netwatcher']['bpf_filter']='tcp and src host 192.0.2.55'
        path.write_text(json.dumps(value))
    (installation/'config/threatfeeds.yaml').write_text('feeds: []\n')
    credentials={kind:dotenv_values(installation/(kind+'.env')) for kind in ('console','sensor','migrate','bootstrap','grants')}
    units=[prefix+'-'+kind+'.service' for kind in ('init','roles','migrate','grants','sensor','console')]
    installed=[]
    owned_state_paths=[]
    async def command(args,check=True,timeout=60):
        child=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:
            async with asyncio.timeout(timeout):out,err=await child.communicate()
            if check and child.returncode:
                (tmp_path/'systemd-command-private.log').write_bytes(err)
                assert child.returncode==0,'Inspect private systemd command log'
            return out.decode()
        finally:
            if child.returncode is None:child.kill();await child.wait()
    try:
        for path in (Path('/run')/prefix,Path('/var/lib')/(prefix+'-sensor'),Path('/var/lib')/(prefix+'-console')):
            assert not path.exists()
            owned_state_paths.append(str(path))
        await command(['sudo','-n','chown','-hR','root:root',str(installation),str(source)])
        for name in units:
            await command(['sudo','-n','install','-m','0644',str(installation/'systemd'/name),'/run/systemd/system/'+name])
            installed.append(name)
        await command(['sudo','-n','systemctl','daemon-reload'])
        await command(['sudo','-n','systemctl','start',prefix+'-sensor',prefix+'-console'])
        async with httpx.AsyncClient(base_url=f'http://127.0.0.1:{port}',timeout=5) as client:
            async with asyncio.timeout(45):
                while True:
                    try:
                        if (await client.get('/health')).status_code==200:break
                    except httpx.HTTPError:pass
                    await asyncio.sleep(1)
            login=await client.post('/api/auth/login',json={
                'username':credentials['console']['NETWATCHER_LOGIN_USERNAME'],
                'password':credentials['console']['NETWATCHER_LOGIN_PASSWORD']})
            assert login.status_code==200
            headers={'Authorization':'Bearer '+login.json()['token']}
            async with asyncio.timeout(30):
                while True:
                    state=await client.get('/api/engines/port_scan',headers=headers)
                    if state.status_code==200:break
                    await asyncio.sleep(1)
            request_id=str(uuid4())
            changed=await client.put('/api/engines/port_scan/config',headers=headers,json={
                'request_id':request_id,'base_version':state.json()['base_version'],'config':{'threshold':7}})
            assert changed.status_code==200
            audit=await client.get('/api/audit/changes/'+request_id,headers=headers)
            assert audit.status_code==200 and audit.json()['outcome']=='applied'
            previous=audit.json()['entries']
            await command(['sudo','-n','systemctl','stop',prefix+'-sensor',prefix+'-console'])
            for job in ('init','migrate','grants'):
                await command(['sudo','-n','systemctl','restart',prefix+'-'+job])
            await command(['sudo','-n','systemctl','start',prefix+'-sensor',prefix+'-console'])
            async with asyncio.timeout(45):
                while True:
                    try:
                        restored=await client.get('/api/engines/port_scan',headers=headers)
                        if restored.status_code==200:break
                    except httpx.HTTPError:pass
                    await asyncio.sleep(1)
            assert restored.json()['engine']['config']['threshold']==7
            stored=await client.get('/api/audit/changes/'+request_id,headers=headers)
            assert stored.status_code==200 and stored.json()['entries']==previous
        for kind,user,capabilities in (('console',console,0),('sensor',sensor,1<<13)):
            name=prefix+'-'+kind
            pid=int((await command(['systemctl','show',name,'--property=MainPID','--value'])).strip())
            status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
            assert int(status['Uid'].split()[1])==user.pw_uid
            assert int(status['CapEff'],16)==int(status['CapPrm'],16)==int(status['CapAmb'],16)==capabilities
            assert status['NoNewPrivs'].strip()=='1'
            exposed=await command(['systemctl','show',name,'--property=Environment'])
            for settings in credentials.values():
                for key,value in settings.items():
                    if key.endswith(('PASSWORD','SECRET')):assert value not in exposed
        # 일반 콘솔은 루트 소유 bootstrap 자격증명을 직접 읽을 수 없다.
        process=await asyncio.create_subprocess_exec('sudo','-n','-u',console.pw_name,'test','-r',str(installation/'bootstrap.env'))
        assert await process.wait()!=0
    finally:
        for name in installed:
            log=await command(['sudo','-n','journalctl','-u',name,'--no-pager','--output=cat'],check=False)
            path=tmp_path/(name+'-private.log');path.write_text(log);path.chmod(0o600)
        if installed:
            await command(['sudo','-n','systemctl','stop',*installed],check=False)
            for name in installed:
                await command(['sudo','-n','rm','--','/run/systemd/system/'+name],check=False)
            await command(['sudo','-n','systemctl','daemon-reload'],check=False)
            await command(['sudo','-n','systemctl','reset-failed',*installed],check=False)
        import psycopg2
        from psycopg2 import sql
        with psycopg2.connect(host=pg['host'],port=pg['port'],dbname=pg['database'],user=pg['username'],password=pg['password']) as admin:
            admin.autocommit=True
            with admin.cursor() as cur:
                cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
                for kind in ('migrate','sensor','console'):
                    name=credentials[kind]['NETWATCHER_DB_USER']
                    cur.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)',(name,))
                    if cur.fetchone()[0]:
                        cur.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(name)))
                        cur.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(name)))
        targets=[str(stage),*owned_state_paths]
        # 모두 위에서 부재를 확인하고 이 시험에서만 생성한 고유 경로다.
        await command(['sudo','-n','rm','-rf','--',*targets],check=False)
