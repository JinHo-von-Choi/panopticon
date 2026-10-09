"""실제 Compose의 분리 콘솔·센서·공유 소켓을 HTTP까지 연결한다."""

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from scripts.install_native import prepare_native_installation
from scripts.install_eve import dotenv_value
from dotenv import dotenv_values
from tests.test_netflow.test_parser import _make_v5_packet


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh_database", [False, True])
async def test_actual_compose_native_console_reads_real_sensor(db,config,tmp_path,fresh_database):
    postgres=os.environ.get('PANOPTICON_TEST_PG_CONTAINER')
    sensor_image=os.environ.get('PANOPTICON_NATIVE_SENSOR_IMAGE')
    console_image=os.environ.get('PANOPTICON_NATIVE_CONSOLE_IMAGE')
    if not all((postgres,sensor_image,console_image)):pytest.skip('Provide owned PostgreSQL and current native images')
    environment=prepare_native_installation(tmp_path/'installation','lo')
    values=dotenv_values(environment)
    if not fresh_database:
        values.update({'NETWATCHER_DB_NAME':os.environ['NETWATCHER_DB_NAME'],
            'NETWATCHER_DB_USER':os.environ['NETWATCHER_DB_USER'],
            'NETWATCHER_DB_PASSWORD':os.environ['NETWATCHER_DB_PASSWORD']})
    environment.write_text('\n'.join(f'{key}={dotenv_value(value)}' for key,value in values.items())+'\n')
    schema='netwatcher' if fresh_database else 'compose_roles_'+uuid4().hex[:12]
    credentials={kind:dotenv_values(environment.parent/(kind+'.env')) for kind in ('console','sensor','migrate','bootstrap','grants')}
    for kind,settings in credentials.items():
        settings['NETWATCHER_DB_NAME']=values['NETWATCHER_DB_NAME']
        settings['NETWATCHER_DB_SEARCH_PATH']=schema+',public'
        if kind=='bootstrap':
            settings['NETWATCHER_DB_USER']=values['NETWATCHER_DB_USER']
            settings['NETWATCHER_DB_PASSWORD']=values['NETWATCHER_DB_PASSWORD']
        (environment.parent/(kind+'.env')).write_text('\n'.join(f'{key}={dotenv_value(value)}' for key,value in settings.items())+'\n')
    sensor_path=environment.parent/'config/sensor.yaml'
    sensor=json.loads(sensor_path.read_text());sensor['netwatcher']['postgresql']['search_path']=schema+',public';sensor['netwatcher']['promiscuous']=False
    sensor['netwatcher']['bpf_filter']='tcp and src host 192.0.2.55'
    sensor['netwatcher']['netflow'] = {'enabled': True, 'host': '127.0.0.1', 'port': 2055, 'engines': {
        'flow_port_scan': {'enabled': True, 'threshold': 20, 'window_seconds': 60},
        'flow_data_exfil': {'enabled': False},
    }}
    sensor_path.write_text(json.dumps(sensor))
    console_path=environment.parent/'config/console.yaml'
    console_config=json.loads(console_path.read_text());console_config['netwatcher']['postgresql']['search_path']=schema+',public'
    console_path.write_text(json.dumps(console_config))
    (environment.parent/'config/threatfeeds.yaml').write_text('feeds: []\n')
    network='panopticon-compose-'+uuid4().hex[:12]
    override=tmp_path/'override.yaml'
    override.write_text(f'''services:
  netwatcher:
    image: {console_image}
    ports: !override
      - target: 38585
        published: "0"
        host_ip: 127.0.0.1
    environment:
      NETWATCHER_SKIP_DOTENV: "1"
  db-migrate:
    image: {console_image}
  native-db-roles:
    image: {console_image}
  native-db-grants:
    image: {console_image}
  native-init:
    image: {sensor_image}
  native-sensor:
    image: {sensor_image}
    network_mode: !reset null
    environment:
      NETWATCHER_DB_HOST: db
      NETWATCHER_DB_PORT: "5432"
networks:
  default:
    external: true
    name: {network}
''')
    env={key:value for key,value in os.environ.items() if not key.startswith(('NETWATCHER_','PANOPTICON_'))}
    compose=['docker','compose','--env-file',str(environment),'-f','docker-compose.yml',
             '-f','docker-compose.native.yml','-f',str(override)]
    if fresh_database:compose += ['--profile','db','--profile','migrate']
    async def command(args,*,check=True,timeout=45):
        child=await asyncio.create_subprocess_exec(*args,env=env,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try:
            async with asyncio.timeout(timeout):out,err=await child.communicate()
            if check:
                if child.returncode:
                    (tmp_path/'private-compose-error.log').write_bytes(err)
                assert child.returncode==0,'Inspect private Compose error log'
            return out.decode()
        finally:
            if child.returncode is None:child.kill();await child.wait()
    attached=False
    try:
        await command(['docker','network','create',network])
        if fresh_database:
            await command([*compose,'up','-d','--no-build','--wait','db'],timeout=60)
            await command([*compose,'run','--rm','--no-deps','native-db-roles'],timeout=60)
            await command([*compose,'run','--rm','--no-deps','db-migrate'],timeout=60)
        else:
            await command(['docker','network','connect','--alias','db',network,postgres]);attached=True
        await command([*compose,'up','-d','--no-build','netwatcher','native-sensor'])
        address=(await command([*compose,'port','netwatcher','38585'])).strip()
        async with httpx.AsyncClient(base_url='http://'+address,timeout=5) as client:
            async with asyncio.timeout(45):
                while True:
                    try:
                        if (await client.get('/health')).status_code==200:break
                    except httpx.HTTPError:pass
                    await asyncio.sleep(.1)
            response=await client.post('/api/auth/login',json={'username':credentials['console']['NETWATCHER_LOGIN_USERNAME'],
                'password':credentials['console']['NETWATCHER_LOGIN_PASSWORD']})
            assert response.status_code==200
            headers={'Authorization':'Bearer '+response.json()['token']}
            async def assert_flow_alert(source):
                container=(await command([*compose,'ps','-q','native-sensor'])).strip()
                payload=_make_v5_packet([{'src_ip':source,'dst_ip':'203.0.113.9','dst_port':port}
                                         for port in range(100,105)])
                await command(['docker','exec',container,'python','-c',
                    'import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(bytes.fromhex(sys.argv[1]),("127.0.0.1",2055));s.close()',
                    payload.hex()])
                async with asyncio.timeout(15):
                    while True:
                        result=await client.get('/api/events',headers=headers,
                            params={'engine':'flow_port_scan','source_ip':source})
                        assert result.status_code==200
                        if result.json()['events']:break
                        await asyncio.sleep(1)
                assert result.json()['events'][0]['source_ip']==source
            async with asyncio.timeout(30):
                while True:
                    response=await client.get('/api/engines',headers=headers)
                    if response.status_code==200:break
                    await asyncio.sleep(1)
            assert 'port_scan' in [entry['name'] for entry in response.json()['engines']]
            state=await client.get('/api/engines/port_scan',headers=headers)
            assert state.status_code==200 and state.json()['engine']['enabled'] is True
            request_id=str(uuid4())
            changed=await client.put('/api/engines/port_scan/config',headers=headers,json={
                'request_id':request_id,'base_version':state.json()['base_version'],'config':{'threshold':7}})
            assert changed.status_code==200
            confirmed=await client.get('/api/engines/port_scan',headers=headers)
            assert confirmed.status_code==200 and confirmed.json()['engine']['config']['threshold']==7

            audit=await client.get('/api/audit/changes/'+request_id,headers=headers)
            assert audit.status_code==200
            assert {'sensor_change_prepared','sensor_change_applied'} <= {entry['action'] for entry in audit.json()['entries']}
            flow=await client.get('/api/engines/flow_port_scan',headers=headers)
            assert flow.status_code==200 and flow.json()['engine']['config']['threshold']==20
            disabled_flow=await client.get('/api/engines/flow_data_exfil',headers=headers)
            assert disabled_flow.status_code==200 and disabled_flow.json()['engine']['enabled'] is False
            flow_request_id=str(uuid4())
            flow_changed=await client.put('/api/engines/flow_port_scan/config',headers=headers,json={
                'request_id':flow_request_id,'base_version':flow.json()['base_version'],'config':{'threshold':5}})
            assert flow_changed.status_code==200 and flow_changed.json()['status']=='applied'
            await assert_flow_alert('192.0.2.83')
            flow_audit=await client.get('/api/audit/changes/'+flow_request_id,headers=headers)
            assert flow_audit.status_code==200 and flow_audit.json()['outcome']=='applied'

            sensor_container=(await command([*compose,'ps','-q','native-sensor'])).strip()
            age_completed='''import os,sys,psycopg2
with psycopg2.connect(host=os.environ['NETWATCHER_DB_HOST'],port=os.environ['NETWATCHER_DB_PORT'],
 dbname=os.environ['NETWATCHER_DB_NAME'],user=os.environ['NETWATCHER_DB_USER'],
 password=os.environ['NETWATCHER_DB_PASSWORD'],options='-c search_path='+os.environ.get('NETWATCHER_DB_SEARCH_PATH','netwatcher,public')) as conn:
 with conn.cursor() as cur:
  cur.execute("UPDATE sensor_control_claims SET completed_at=clock_timestamp()-INTERVAL '8 days' WHERE request_id=%s AND status='completed'",(sys.argv[1],))
  assert cur.rowcount==1
'''
            await command(['docker','exec',sensor_container,'python','-c',age_completed,request_id])

            # 공개 업데이트 절차에서 기존 설정·계정·감사 이력을 유지한다.
            previous_audit=audit.json()['entries']
            await command([*compose,'stop','netwatcher','native-sensor'])
            for job in ('db-migrate','native-db-grants'):
                await command([*compose,'run','--rm','--no-deps',job],timeout=60)
            await command([*compose,'up','-d','--no-build','netwatcher','native-sensor'])
            new_address=(await command([*compose,'port','netwatcher','38585'])).strip()
            # 컨테이너 재생성 시 임의 공개 포트가 바뀔 수 있다.
            client.base_url='http://'+new_address
            async with asyncio.timeout(45):
                while True:
                    try:
                        restored=await client.get('/api/engines/port_scan',headers=headers)
                        if restored.status_code==200:break
                    except httpx.HTTPError:pass
                    await asyncio.sleep(1)
            assert restored.json()['engine']['config']['threshold']==7
            restored_audit=await client.get('/api/audit/changes/'+request_id,headers=headers)
            assert restored_audit.status_code==200
            assert restored_audit.json()['entries']==previous_audit
            restored_flow=await client.get('/api/engines/flow_port_scan',headers=headers)
            assert restored_flow.status_code==200 and restored_flow.json()['engine']['config']['threshold']==5
            await assert_flow_alert('192.0.2.84')
            login=await client.post('/api/auth/login',json={
                'username':credentials['console']['NETWATCHER_LOGIN_USERNAME'],
                'password':credentials['console']['NETWATCHER_LOGIN_PASSWORD']})
            assert login.status_code==200
            next_request_id=str(uuid4())
            updated=await client.put('/api/engines/port_scan/config',headers=headers,json={
                'request_id':next_request_id,'base_version':restored.json()['base_version'],
                'config':{'threshold':8}})
            assert updated.status_code==200
            latest=await client.get('/api/engines/port_scan',headers=headers)
            assert latest.status_code==200 and latest.json()['engine']['config']['threshold']==8
            next_audit=await client.get('/api/audit/changes/'+next_request_id,headers=headers)
            assert next_audit.status_code==200 and next_audit.json()['outcome']=='applied'
            archived=await client.get('/api/audit/changes/'+request_id,headers=headers)
            assert archived.status_code==200 and archived.json()['outcome']=='applied'
            assert 'sensor_change_archived' in {entry['action'] for entry in archived.json()['entries']}
            rejected=await client.put('/api/engines/port_scan/config',headers=headers,json={
                'request_id':request_id,'base_version':latest.json()['base_version'],'config':{'threshold':40}})
            assert rejected.status_code==409 and rejected.json()['detail']['code']=='sensor_request_expired'
            preserved=await client.get('/api/audit/changes/'+request_id,headers=headers)
            assert preserved.status_code==200 and preserved.json()['outcome']=='applied'

            sensor_id=(await command([*compose,'ps','-q','native-sensor'])).strip()
            async with asyncio.timeout(15):
                while True:
                    target=json.loads(await command(['docker','inspect',sensor_id]))[0]
                    started=datetime.fromisoformat(target['State']['StartedAt'])
                    if (datetime.now(timezone.utc)-started).total_seconds() >= 10:break
                    await asyncio.sleep(1)
            assert target['State']['Running'] and target['State']['Pid'] > 1
            assert target['Config']['Image']==sensor_image
            # docker kill은 수동 종료로 처리하므로 호스트 PID의 시험 센서에 직접 신호를 보낸다.
            await command(['docker','run','--rm','--pid=host','--network=none',
                '--cap-drop=ALL','--cap-add=KILL','--security-opt=no-new-privileges:true',
                '--read-only','--entrypoint=python',sensor_image,'-c',
                'import os,signal,sys;os.kill(int(sys.argv[1]),signal.SIGKILL)',
                str(target['State']['Pid'])])
            async with asyncio.timeout(90):
                while True:
                    process=json.loads(await command(['docker','inspect',sensor_id]))[0]
                    if process['RestartCount'] >= 1 and process['State']['Running']:
                        recovered=await client.get('/api/engines/port_scan',headers=headers)
                        if recovered.status_code==200:break
                    await asyncio.sleep(1)
            assert recovered.json()['engine']['config']['threshold']==8
            preserved_audit=await client.get('/api/audit/changes/'+next_request_id,headers=headers)
            assert preserved_audit.status_code==200 and preserved_audit.json()['outcome']=='applied'
            recovered_flow=await client.get('/api/engines/flow_port_scan',headers=headers)
            assert recovered_flow.status_code==200 and recovered_flow.json()['engine']['config']['threshold']==5
            await assert_flow_alert('192.0.2.85')
            preserved_flow_audit=await client.get('/api/audit/changes/'+flow_request_id,headers=headers)
            assert preserved_flow_audit.status_code==200 and preserved_flow_audit.json()['outcome']=='applied'

            ids={name:(await command([*compose,'ps','-q',name])).strip() for name in ('netwatcher','native-sensor')}
            console=json.loads(await command(['docker','inspect',ids['netwatcher']]))[0]
            sensor=json.loads(await command(['docker','inspect',ids['native-sensor']]))[0]
            assert console['Config']['User']=='10001:10001'
            assert console['HostConfig']['CapDrop']==['ALL'] and not console['HostConfig']['CapAdd']
            assert sensor['HostConfig']['CapDrop']==['ALL'] and sensor['HostConfig']['CapAdd'] in (['NET_RAW'],['CAP_NET_RAW'])
            assert console['HostConfig']['ReadonlyRootfs'] and sensor['HostConfig']['ReadonlyRootfs']
            code="from pathlib import Path;import json;s=dict(line.split(':',1) for line in Path('/proc/1/status').read_text().splitlines() if ':' in line);print(json.dumps({k:s[k].strip() for k in ('Uid','CapEff','CapPrm','CapAmb','NoNewPrivs')}))"
            for name,expected in (('netwatcher',0),('native-sensor',1<<13)):
                status=json.loads(await command(['docker','exec',ids[name],'python','-c',code]))
                assert int(status['CapEff'],16)==int(status['CapPrm'],16)==expected
                assert int(status['CapAmb'],16)==0 and status['NoNewPrivs']=='1'
            for name in ('netwatcher','native-sensor'):
                process_env=json.loads(await command(['docker','inspect','--format','{{json .Config.Env}}',ids[name]]))
                for kind in ('bootstrap','migrate','grants'):
                    assert not any(credentials[kind]['NETWATCHER_DB_PASSWORD'] in item for item in process_env)

    finally:
        for name in ('netwatcher','native-sensor','native-init','native-db-roles','native-db-grants','db-migrate'):
            logs=await command([*compose,'logs','--no-color',name],check=False)
            log=tmp_path/(name+'-private.log');log.write_text(logs);log.chmod(0o600)
        await command([*compose,'down','--volumes','--remove-orphans'],check=False)
        if attached:
            await command(['docker','network','disconnect',network,postgres],check=False)
            import psycopg2
            from psycopg2 import sql
            with psycopg2.connect(host=os.environ['NETWATCHER_DB_HOST'],port=os.environ['NETWATCHER_DB_PORT'],
                dbname=values['NETWATCHER_DB_NAME'],user=values['NETWATCHER_DB_USER'],password=values['NETWATCHER_DB_PASSWORD']) as admin:
                admin.autocommit=True
                with admin.cursor() as cur:
                    cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
                    for kind in ('migrate','console','sensor'):
                        name=credentials[kind]['NETWATCHER_DB_USER']
                        cur.execute('SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=%s)',(name,))
                        if cur.fetchone()[0]:
                            cur.execute(sql.SQL('DROP OWNED BY {}').format(sql.Identifier(name)))
                            cur.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(name)))
        await command(['docker','network','rm',network],check=False)
