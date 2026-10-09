"""직접 캡처 기본 CLI는 합쳐진 웹·센서 실행으로 되돌아가지 않는다."""

import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


@pytest.mark.parametrize('native,message', [
    ({'console':{'separate':False}}, 'false는 지원하지 않습니다'),
    ({'console':{'separate':'false'}}, 'must be boolean'),
    ({}, '센서 소켓 연결 설정이 필요합니다'),
    ({'control':{'enabled':False}}, '센서 소켓 연결 설정이 필요합니다'),
])
def test_cli_rejects_unsafe_native_configuration_before_capture_import(tmp_path,native,message):
    path=tmp_path/'native.yaml'
    path.write_text(yaml.safe_dump({'netwatcher':{'input':{'mode':'native'},'native':native}}))
    root=Path(__file__).resolve().parents[2]
    code = """
import importlib.abc,runpy,sys
root,config=sys.argv[1:]
sys.path.insert(0,root)
class RejectCapture(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path,target=None):
  if fullname in ('netwatcher.app','netwatcher.capture','scapy') or fullname.startswith(('netwatcher.capture.','scapy.')):
   raise AssertionError('Unsafe default console imported capture: '+fullname)
sys.meta_path.insert(0,RejectCapture())
sys.argv=['netwatcher','-c',config]
runpy.run_module('netwatcher',run_name='__main__')
"""
    env={key:value for key,value in os.environ.items() if not key.startswith('NETWATCHER_')}
    env['NETWATCHER_SKIP_DOTENV']='1'
    result=subprocess.run([sys.executable,'-I','-c',code,str(root),str(path)],env=env,
                          capture_output=True,text=True,timeout=10)
    assert result.returncode == 2
    assert message in result.stderr
    assert 'AssertionError' not in result.stderr
