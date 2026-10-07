# 설치와 업데이트

이 가이드는 Linux 서버에 Panopticon과 PostgreSQL을 설치하는 방법을 설명합니다. Docker Compose 설치를 권장합니다. 패킷 캡처가 필요한 네트워크 인터페이스와 저장 공간을 먼저 준비하세요.

## 1. 관측 위치 선택

전체 구간을 관찰하려면 스위치의 미러링 포트(SPAN)에 센서를 연결하고, 관찰할 포트·VLAN을 미러링 대상으로 지정합니다. 일반 포트에 설치했다면 다른 장치 사이의 통신이 보이지 않을 수 있습니다.

```bash
ip -br link
```

사용할 인터페이스 이름을 확인해 `config/default.yaml`의 `netwatcher.interface`에 입력합니다. 자동 선택보다 명시적인 선택을 권장합니다.

## 2. 소스와 접속 정보 준비

```bash
git clone https://github.com/JinHo-von-Choi/panopticon.git
cd panopticon
git checkout v0.4.0
cp .env.example .env
chmod 600 .env
```

`.env`를 편집해 다음 값을 설정합니다. 예시 비밀번호와 토큰은 실제 값으로 바꾸세요.

| 항목 | 설정 |
| --- | --- |
| `NETWATCHER_DB_HOST` | 함께 설치할 DB는 `127.0.0.1` |
| `NETWATCHER_DB_PORT` | 함께 설치할 DB는 `5432` |
| `NETWATCHER_DB_NAME` | `netwatcher` |
| `NETWATCHER_DB_USER` | `netwatcher` |
| `NETWATCHER_DB_PASSWORD` | 새 DB 비밀번호 |
| `NETWATCHER_LOGIN_ENABLED` | `true` |
| `NETWATCHER_LOGIN_USERNAME` | 관리자 로그인 이름 |
| `NETWATCHER_LOGIN_PASSWORD` | 관리자 로그인 비밀번호 |
| `NETWATCHER_JWT_SECRET` | 재시작 후에도 유지할 충분히 긴 무작위 문자열 |

JWT 서명 키는 다음 명령으로 생성할 수 있습니다.

```bash
openssl rand -hex 32
```

사용하지 않는 Slack·Discord·Telegram 항목은 `.env`에서 삭제합니다. DB 접속 정보와 로그인 정보는 서로 다른 비밀번호를 사용하세요.

## 3. Docker Compose로 시작

새 DB를 함께 설치하는 경우 다음 순서로 실행합니다.

```bash
docker compose --profile db up -d db
docker compose --profile db --profile migrate run --rm db-migrate
docker compose --profile db up -d --build netwatcher
```

기존 PostgreSQL을 사용한다면 `.env`에 해당 접속 정보를 입력하고 다음 명령을 사용합니다.

```bash
docker compose --profile migrate run --rm db-migrate
docker compose up -d --build netwatcher
```

컨테이너는 호스트 네트워크와 패킷 캡처 권한을 사용합니다. DB는 기본 Compose 구성에서 `127.0.0.1:5432`에만 노출됩니다. 같은 포트를 이미 사용하는 DB가 있다면 기존 DB를 사용하거나 Compose의 포트와 `.env`를 함께 변경하세요.

## 4. 로그인과 첫 확인

설치 서버에서 `http://127.0.0.1:38585`를 열어 로그인합니다. 다른 컴퓨터에서 접속하려면 SSH 포트 전달을 사용할 수 있습니다. 아래 `user@server`를 실제 접속 대상으로 바꾸세요.

```bash
ssh -L 38585:127.0.0.1:38585 user@server
```

그다음 접속한 컴퓨터에서 같은 주소를 엽니다. LAN에 직접 공개할 경우에는 [인증과 HTTPS 설정](CONFIGURATION.md#인증과-https)을 먼저 적용하세요.

설치 점검에서 인터페이스·관측 범위·저장소를 확인하고, 자신이 관리하는 장치의 통신이 사건 또는 장치 목록에 나타나는지 확인합니다. `/health`는 프로세스 응답, `/ready`는 DB와 센서 등 주요 구성요소의 준비 상태를 확인하는 주소입니다.

```bash
curl --fail http://127.0.0.1:38585/ready
docker compose logs --tail=100 netwatcher
```

## 호스트에서 직접 실행

Docker를 사용하지 않을 때는 Python 3.12 이상과 libpcap, 접속 가능한 PostgreSQL을 준비합니다. Debian·Ubuntu의 예시는 다음과 같습니다.

```bash
sudo apt-get install libpcap-dev python3-venv
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m alembic upgrade head
sudo .venv/bin/python -m netwatcher -c config/default.yaml
```

계속 실행할 서비스로 설치하려면 `netwatcher.service`의 `WorkingDirectory`, `EnvironmentFile`, `ExecStart`를 실제 설치 경로에 맞춰 수정한 뒤 설치합니다.

```bash
sudo install -m 644 netwatcher.service /etc/systemd/system/netwatcher.service
sudo systemctl daemon-reload
sudo systemctl enable --now netwatcher
```

제공된 서비스는 캡처를 위해 root로 실행합니다. 웹 프로세스만 별도 권한으로 분리해 실행하는 배포 방식은 아직 제공하지 않습니다.

## 업데이트

업데이트 전에 [DB·설정·증거 백업](OPERATIONS-GUIDE.md#백업)을 완료합니다. 변경 기록에서 호환성 안내를 확인하고, 사용할 릴리스 태그로 이동합니다.

```bash
git fetch --tags
git checkout v0.4.0
docker compose stop netwatcher
docker compose --profile migrate run --rm --build db-migrate
docker compose up -d --build netwatcher
```

준비 상태와 최근 사건을 확인한 뒤 운영을 재개합니다. 정상 동작을 확인하기 전에는 백업을 삭제하지 마세요. 이전 버전으로 돌아갈 때는 애플리케이션 버전과 DB 스키마의 호환성을 함께 확인해야 합니다.

## 설치가 되지 않을 때

| 증상 | 확인할 내용 |
| --- | --- |
| DB 연결 실패 | `.env`의 주소·포트·계정, DB 기동 상태, 연결 허용 설정 |
| 인터페이스를 찾지 못함 | `ip -br link`의 이름과 `netwatcher.interface` |
| 다른 장치가 보이지 않음 | SPAN 대상 포트·VLAN, 센서 연결 위치 |
| 로그인 실패 | 로그인 환경변수, 입력한 계정, 재시도 제한 |
| 시작 시 지원 구성 오류 | 오류에 표시된 설정 경로와 [지원 범위](CONFIGURATION.md#지원-범위) |
| 설정을 저장할 수 없음 | 기본 Docker 설정은 읽기 전용. [쓰기 허용](CONFIGURATION.md#대시보드에서-설정-저장) 참고 |
