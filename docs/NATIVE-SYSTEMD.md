# 호스트에서 센서와 콘솔 실행하기

직접 패킷을 캡처할 때 Docker 대신 systemd로 센서와 웹 콘솔을 운영하는 방법입니다. 환경 구성에는 Linux, Python 3.12 이상, libpcap, 접속 가능한 PostgreSQL, 그리고 `LoadCredential`을 지원하는 systemd가 필요합니다. 캡처 인터페이스에는 관측할 트래픽이 들어와야 하므로, 다른 장치 사이의 통신을 보려면 SPAN 또는 TAP 연결을 준비해야 합니다.

센서와 콘솔은 서로 다른 일반 사용자로 실행합니다. 센서에만 `NET_RAW`를 부여하고 콘솔에는 capability를 주지 않습니다. DB 초기화·마이그레이션은 별도 서비스가 맡습니다. 각 서비스의 비밀번호는 systemd 자격증명으로 전달하며 서비스 파일 안에는 적지 않습니다.

## 새 설치

릴리스 소스를 `/opt/panopticon`에 풀고 일반 사용자가 소스 파일을 변경할 수 없도록 소유권과 권한을 설정합니다. 서비스 사용자가 소스와 상위 디렉터리를 읽고 통과할 수 있어야 합니다. 해당 디렉터리에서 Python 환경을 준비합니다.

```bash
sudo python3 -m venv /opt/panopticon/.venv
sudo /opt/panopticon/.venv/bin/pip install --require-hashes -r /opt/panopticon/requirements.lock
```

처음 설치하는 호스트에는 전용 계정을 만듭니다. 기존 계정이 있다면 새로 만들지 않고 UID가 0이 아닌 서로 다른 계정인지 확인합니다.

```bash
sudo useradd --system --user-group --home-dir /var/lib/panopticon-native-console --shell /usr/sbin/nologin panopticon-console
sudo useradd --system --user-group --home-dir /var/lib/panopticon-native-sensor --shell /usr/sbin/nologin panopticon-sensor
```

작업 디렉터리에 소유자만 읽을 수 있는 `db-bootstrap.env`를 만듭니다.

```bash
install -m 0600 /dev/null db-bootstrap.env
```

아래 형식으로 대상 DB의 관리 계정 정보를 입력합니다. 실제 연결 정보로 값을 넣어야 합니다. 이 계정은 DB 역할과 스키마를 생성할 때 사용합니다. 기존 스키마 소유권을 가져오지는 않으므로 새 DB나 아직 쓰지 않는 스키마를 준비해야 합니다.

```dotenv
NETWATCHER_DB_HOST='127.0.0.1'
NETWATCHER_DB_PORT='5432'
NETWATCHER_DB_NAME='panopticon'
NETWATCHER_DB_USER='관리 계정 이름'
NETWATCHER_DB_PASSWORD='관리 계정 비밀번호'
```

`eth0`를 실제 캡처 인터페이스 이름으로 바꾸고 설치 파일을 만듭니다. 다른 스키마를 쓰려면 `--schema 스키마이름`을 붙입니다. 기존 출력 디렉터리는 덮어쓰지 않습니다.

```bash
/opt/panopticon/.venv/bin/python /opt/panopticon/scripts/install_native_systemd.py \
  --interface eth0 --database-env db-bootstrap.env \
  --console-user panopticon-console --sensor-user panopticon-sensor \
  --output installation-native-systemd
```

생성된 설정과 서비스 파일을 설치합니다. 비밀 파일은 root 소유와 0600 권한으로 유지합니다. 서비스 사용자가 직접 읽는 설정 파일에는 비밀번호를 넣지 않습니다.

```bash
sudo install -d -m 0755 /etc/panopticon-native/config
sudo install -m 0600 installation-native-systemd/*.env /etc/panopticon-native/
sudo install -m 0644 installation-native-systemd/config/*.yaml /etc/panopticon-native/config/
sudo install -m 0644 installation-native-systemd/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now panopticon-native-sensor panopticon-native-console
```

첫 기동은 DB 역할 생성·마이그레이션·권한 부여와 센서 저장 디렉터리 초기화를 순서대로 수행합니다. 초기 로그인 정보는 생성된 `installation-native-systemd/console.env`에 들어 있습니다. `http://127.0.0.1:38585`에서 로그인하고 **운영 상태**에서 센서 연결과 관측 범위를 확인합니다. 원격 접속 시에는 [SSH 포트 전달](INSTALL.md#로그인과-첫-확인)이나 [HTTPS 설정](CONFIGURATION.md#인증과-https)을 이용합니다.

설치에 쓴 관리 계정 파일과 생성된 자격증명은 외부에 공개하거나 소스 저장소에 올리지 않습니다. 설치 도구는 호스트의 계정·DB·systemd 설정을 직접 건드리지 않고 안내된 명령에 쓸 파일만 만듭니다.

## 저장 위치와 권한

센서 설정·증거·로그는 `/var/lib/panopticon-native-sensor`에 두고, 콘솔 로그는 `/var/lib/panopticon-native-console`에 둡니다. 센서 제어 소켓은 `/run/panopticon-native/sensor.sock`입니다. systemd가 저장·실행 디렉터리를 해당 사용자 소유로 준비합니다. 초기화 서비스를 다시 돌려도 이미 변경된 센서 설정은 덮어쓰지 않습니다.

센서와 콘솔의 DB 계정은 서로 분리되어 있습니다. 런타임 계정은 테이블을 만들거나 감사 기록을 수정·삭제할 수 없습니다. 콘솔은 센서의 비공개 저장 디렉터리 대신 제어 소켓을 통해 증거를 요청합니다.

## 상태 확인과 재시작

```bash
systemctl status panopticon-native-sensor panopticon-native-console
sudo journalctl -u panopticon-native-sensor -u panopticon-native-console --since '10 minutes ago'
sudo systemctl restart panopticon-native-sensor panopticon-native-console
```

센서가 비정상 종료되면 systemd가 다시 띄웁니다. 강제 종료 직후에는 이전 실행의 DB 소유권이 만료될 때까지 연결이 지연될 수 있습니다. 연결이 복구되면 엔진 설정과 마지막 변경의 감사 이력을 살펴봅니다. 소유를 확인할 수 없는 소켓을 임의로 지우거나 결과가 미확정인 변경을 다시 실행하지 않습니다.

## 업데이트

[DB·설정·증거 백업](OPERATIONS-GUIDE.md#백업)을 마친 후 두 서비스를 중지하고 `/opt/panopticon` 소스와 Python 의존성을 업데이트합니다. 기존 `/etc/panopticon-native` 자격증명과 설정, `/var/lib` 저장 디렉터리는 그대로 유지합니다. 새 설치 도구로 기존 비밀번호를 바꾸지 않습니다.

```bash
sudo systemctl stop panopticon-native-sensor panopticon-native-console
```

소스와 의존성을 준비한 뒤 마이그레이션과 권한 부여를 다시 실행하고 서비스를 시작합니다.

```bash
sudo systemctl restart panopticon-native-migrate
sudo systemctl restart panopticon-native-grants
sudo systemctl start panopticon-native-sensor panopticon-native-console
```

로그인, 센서 연결, 기존 사건·설정·감사 기록을 점검합니다. 서비스 파일을 손보았다면 시작하기 전에 `sudo systemctl daemon-reload`도 실행해야 합니다. 이전 버전으로 되돌릴 때는 [백업 복원 절차](OPERATIONS-GUIDE.md#백업)를 따릅니다.