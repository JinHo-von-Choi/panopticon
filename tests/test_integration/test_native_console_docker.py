"""격리 컨테이너에서 독립 콘솔의 실제 커널 권한 경계를 확인한다."""

import os
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("uid", [0, 1000])
def test_console_refuses_root_and_unprivileged_raw_socket(uid):
    image = os.environ.get("PANOPTICON_NATIVE_SENSOR_IMAGE")
    if not image or not shutil.which("docker"):
        pytest.skip("Provide PANOPTICON_NATIVE_SENSOR_IMAGE for isolated kernel permission checks")
    code = """
import importlib.abc,os,socket,sys
from pathlib import Path
sys.path.insert(0,'/app')
class RejectCapture(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path,target=None):
  if fullname in ('scapy','netwatcher.capture','netwatcher.app','netwatcher.response.blocker') or fullname.startswith(('scapy.','netwatcher.capture.')):
   raise AssertionError('Console imported capture or local blocking: '+fullname)
sys.meta_path.insert(0,RejectCapture())
from netwatcher.native_console import require_unprivileged_console
if os.geteuid()==0:
 try:
  require_unprivileged_console()
 except ValueError:
  print('root refused')
 else:
  raise AssertionError('Root console accepted')
else:
 require_unprivileged_console()
 status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
 assert all(int(status[name].strip(),16)==0 for name in ('CapEff','CapPrm','CapAmb'))
 assert status['NoNewPrivs'].strip()=='1'
 try:
  raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
 except PermissionError:
  print('raw denied')
 else:
  raw.close()
  raise AssertionError('Raw packet socket accepted')
"""
    result = subprocess.run(["docker", "run", "--rm", "--read-only", "--network", "none",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", f"{uid}:{uid}",
        "--entrypoint", "python", image, "-I", "-c", code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == ("root refused" if uid == 0 else "raw denied")


def test_native_console_image_default_user_cannot_open_raw_socket():
    image = os.environ.get('PANOPTICON_NATIVE_CONSOLE_IMAGE')
    if not image or not shutil.which('docker'):
        pytest.skip('Provide PANOPTICON_NATIVE_CONSOLE_IMAGE for default image permission check')
    code = """
import os,socket,sys
sys.path.insert(0,'/app')
from netwatcher.native_console import require_unprivileged_console
assert os.geteuid()==10001
require_unprivileged_console()
try:
 raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
except PermissionError:
 print('default console raw denied')
else:
 raw.close()
 raise AssertionError('Default console opened a raw socket')
"""
    result = subprocess.run(['docker','run','--rm','--read-only','--network','none',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--entrypoint','python',image,
        '-I','-c',code],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr[-2000:]
    assert result.stdout.strip()=='default console raw denied'
