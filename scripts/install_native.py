"""새 직접 캡처 설치의 센서·콘솔 설정과 자격증명을 준비한다."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.install_eve import database_port, dotenv_value


def prepare_native_installation(output, interface, *, username='admin', sensor_id='office-native'):
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('설치 디렉터리가 이미 있습니다. 새 디렉터리를 지정하세요.')
    if not isinstance(interface, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', interface):
        raise ValueError('캡처 인터페이스 이름을 확인하세요.')
    if not isinstance(sensor_id, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,128}', sensor_id):
        raise ValueError('센서 식별자를 확인하세요.')
    if not isinstance(username, str) or not username or len(username) > 64 or any(c in username for c in '\n\r\x00'):
        raise ValueError('관리자 계정 이름을 확인하세요.')
    root = Path(__file__).resolve().parents[1]
    sensor = deepcopy(yaml.safe_load((root/'config/default.yaml').read_text())['netwatcher'])
    sensor.update({'input':{'mode':'native'}, 'interface':interface, 'workers':1,
        'native':{'sensor_id':sensor_id,'heartbeat_seconds':5,'lease_seconds':30,
            'control':{'enabled':True,'socket_path':'/run/panopticon/sensor.sock','allowed_uid':10001,
                       'socket_gid':10001,'expected_uid':0}},
        'auth':{'enabled':True,'multi_user':True}, 'response':{'enabled':False},
        'response_execution':{'enabled':False}, 'ha':{'enabled':False},
        'logging':{'level':'INFO','directory':'/app/data/logs'},
        'threatfeeds':{'config_path':'/app/data/threatfeeds.yaml'}})
    sensor['netflow']['enabled'] = False
    sensor['ai_analyzer']['enabled'] = False
    console = {'input':{'mode':'native'},'native':deepcopy(sensor['native']),
        'auth':deepcopy(sensor['auth']),'response':{'enabled':False},'response_execution':{'enabled':False},
        'web':{'host':'0.0.0.0','port':38585},'logging':{'level':'INFO','directory':'/app/data/logs'}}
    port = database_port()
    project='panopticon-native-'+hashlib.sha256(str(output).encode()).hexdigest()[:10]
    suffix=hashlib.sha256(str(output).encode()).hexdigest()[:10]
    roles={kind:'nw_'+suffix+'_'+kind for kind in ('migrate','console','sensor')}
    passwords={kind:secrets.token_hex(32) for kind in roles}
    database={'NETWATCHER_DB_HOST':'db','NETWATCHER_DB_PORT':'5432','NETWATCHER_DB_NAME':'netwatcher'}
    login={'NETWATCHER_LOGIN_ENABLED':'true','NETWATCHER_LOGIN_USERNAME':username,
           'NETWATCHER_LOGIN_PASSWORD':secrets.token_urlsafe(32),'NETWATCHER_JWT_SECRET':secrets.token_hex(32)}
    values={'COMPOSE_PROJECT_NAME':project,'PANOPTICON_CONFIG_DIR':str(output/'config'),
        'PANOPTICON_ENV_FILE':str(output/'.env'),'PANOPTICON_DB_PUBLISH_PORT':str(port),
        'NETWATCHER_NATIVE_DB_HOST':'127.0.0.1','NETWATCHER_NATIVE_DB_PORT':str(port),
        **database,'NETWATCHER_DB_USER':'panopticon_bootstrap','NETWATCHER_DB_PASSWORD':secrets.token_hex(32)}
    role_names={'PANOPTICON_DB_INSTALLATION':project,**{'PANOPTICON_DB_'+kind.upper()+'_ROLE':name for kind,name in roles.items()}}
    credentials={kind:{**database,'NETWATCHER_DB_USER':roles[kind],'NETWATCHER_DB_PASSWORD':passwords[kind],
                      'NETWATCHER_SKIP_DOTENV':'1'} for kind in roles}
    credentials['console'].update(login)
    credentials['bootstrap']={**database,'NETWATCHER_DB_USER':values['NETWATCHER_DB_USER'],
        'NETWATCHER_DB_PASSWORD':values['NETWATCHER_DB_PASSWORD'],**role_names,
        **{'PANOPTICON_DB_'+kind.upper()+'_PASSWORD':password for kind,password in passwords.items()}}
    credentials['grants']={**credentials['migrate'],**role_names}
    credentials['sensor']['NETWATCHER_LOGIN_ENABLED']='true'
    credentials['sensor']['NETWATCHER_JWT_SECRET']=secrets.token_hex(32)
    for kind in credentials:values['PANOPTICON_'+kind.upper()+'_ENV_FILE']=str(output/(kind+'.env'))
    for config,kind in ((sensor,'sensor'),(console,'console')):
        config['postgresql']={'host':'db','port':5432,'database':'netwatcher','username':roles[kind],
                              'password':'','pool_size':5,'ssl_mode':'disable'}
    environment='\n'.join(f'{key}={dotenv_value(value)}' for key,value in values.items())+'\n'
    output.mkdir(mode=0o700)
    (output/'config').mkdir(mode=0o755)
    (output/'config').chmod(0o755)
    for name,contents,mode in [('.env',environment,0o600),
        ('config/sensor.yaml',json.dumps({'netwatcher':sensor},ensure_ascii=False,indent=2)+'\n',0o644),
        ('config/console.yaml',json.dumps({'netwatcher':console},ensure_ascii=False,indent=2)+'\n',0o644),
        ('config/default.yaml',json.dumps({'netwatcher':console},ensure_ascii=False,indent=2)+'\n',0o644),
        ('config/threatfeeds.yaml',(root/'config/threatfeeds.yaml').read_text(),0o644)]:
        with os.fdopen(os.open(output/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode),'w') as stream:
            stream.write(contents)
        (output/name).chmod(mode)
    for kind,settings in credentials.items():
        path=output/(kind+'.env')
        contents='\n'.join(f'{key}={dotenv_value(value)}' for key,value in settings.items())+'\n'
        with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:stream.write(contents)
        path.chmod(0o600)
    return output/'.env'


def main():
    parser=argparse.ArgumentParser(description='독립 센서와 일반 사용자 콘솔의 새 설치 설정을 생성합니다.')
    parser.add_argument('--interface',required=True)
    parser.add_argument('--output',default='installation-native')
    parser.add_argument('--sensor-id',default='office-native')
    parser.add_argument('--username',default='admin')
    args=parser.parse_args()
    try:
        environment=prepare_native_installation(args.output,args.interface,username=args.username,sensor_id=args.sensor_id)
    except (ValueError,OSError) as error:
        parser.exit(1,'설정 생성 실패: '+(str(error) if isinstance(error,ValueError) else type(error).__name__)+'\n')
    print(f'설정 생성 완료: {environment.parent}')
    print(f'로그인 정보 파일: {environment.parent / "console.env"}')


if __name__ == '__main__':
    main()
