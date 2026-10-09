# 설치와 업데이트

Panopticon은 Suricata EVE 로그를 분석해 경보를 조사하는 콘솔입니다. 기본 패키지 설치 시 패킷 캡처 권한이나 SPAN 포트 구성은 요구하지 않습니다. 다만 Suricata가 검사 대상 트래픽을 넘겨받을 경로는 네트워크 환경에 맞게 따로 마련해 두어야 합니다.

릴리스 파일로 설치하거나 업데이트할 때는 사전에 [릴리스 검증](RELEASE-VERIFICATION.md) 문서에 따라 소스 커밋과 빌드 증명을 대조해 유효성을 점검합니다.

## Docker Compose로 새로 설치하기

Linux 운영체제, Python 3.12 이상, Docker Compose 환경과 읽기 권한이 부여된 Suricata `eve.json` 파일이 필요합니다. 배포 소스 압축을 해제한 뒤 해당 경로로 이동해 설치 스크립트를 실행합니다.

```bash
python3 scripts/install_eve.py --eve-file /var/log/suricata/eve.json
```

설치 도구가 로그 형식과 권한을 점검하고 `installation` 디렉터리에 환경 설정 파일을 구성합니다. DB 암호, 관리자 암호, JWT 키는 스크립트 실행 과정에서 각각 난수로 자동 생성되며, 생성된 로그인 계정 정보는 `installation/.env` 파일에서 확인할 수 있습니다. 작업 경로에 이미 동일한 이름의 설치 디렉터리가 남아 있다면 덮어쓰지 않고 즉시 중단합니다.

로그 파일에 그룹 읽기 권한이 없다면 사전에 권한을 부여해야 합니다. 기본 그룹 외의 다른 그룹 권한으로 파일을 읽을 때는 `--log-gid 그룹번호` 옵션을 추가합니다. 데이터 보존 기간이나 로그 수집 상한선, 입력 식별자 값은 `installation/config/default.yaml`에서 수정할 수 있으며, 자세한 설정 범위와 수집 한계는 [EVE 연결 가이드](EVE.md) 문서를 따릅니다.

```bash
docker compose --env-file installation/.env --profile db up -d db
docker compose --env-file installation/.env --profile db --profile migrate run --rm --build db-migrate
docker compose --env-file installation/.env --profile db up -d --build netwatcher
```

기본 웹 콘솔은 호스트의 `127.0.0.1:38585` 포트로 노출됩니다. 모든 컨테이너는 권한이 제한된 일반 사용자 계정으로 구동되며 컨테이너 내부의 모든 Linux capability를 제거한 상태로 동작합니다. EVE 로그 파일과 루트 파일 시스템은 읽기 전용 상태로 안전하게 마운트됩니다. 컨테이너가 내부 브리지 네트워크를 통해 DB에 접속하므로, 호스트에 노출할 DB 포트에는 초기 구성 단계에서 미사용 중인 임의의 빈 포트가 지정됩니다.

외부에 구축된 별도의 PostgreSQL 인스턴스를 활용할 때는 `installation/.env`에 기재된 DB 주소, 포트, 접속 계정, 비밀번호를 대상 인스턴스 정보에 맞춰 직접 수정합니다. 이때 컨테이너 내부 네트워크에서 도달할 수 있는 호스트 주소를 지정해야 합니다. 외부 DB를 연결할 때는 `--profile db` 옵션을 명령줄에서 제외하고 데이터베이스 마이그레이션과 콘솔 컨테이너를 차례로 시작합니다.

## 로그인과 첫 확인

설치를 마친 서버에서 웹 브라우저로 `http://127.0.0.1:38585` 주소에 접속한 뒤 앞서 발급된 관리자 계정으로 로그인합니다. 원격 환경에서 콘솔에 접근해야 한다면 SSH 포트 포워딩을 구성해 접속 통로를 열어둡니다.

```bash
ssh -L 38585:127.0.0.1:38585 user@server
```

터널링을 연결한 원격 PC의 웹 브라우저에서 `http://127.0.0.1:38585` 주소를 열어 정상 화면을 확인합니다. 내부 LAN 전체 공개나 TLS 암호화 적용 절차는 [인증과 HTTPS 설정](CONFIGURATION.md#인증과-https) 문서의 안내를 준수합니다.

대시보드의 **운영 상태** 화면으로 이동하여 설치 점검 결과와 관측 범위를 차례로 확인합니다. 입력 스트림 연결 상태, 로그 누락 가능성, 저장 공간 보존 한도를 함께 점검합니다. 실제 Suricata 탐지 경보 한 건이 사건 목록 화면에 반영되는지도 검증합니다. `/health` 엔드포인트는 애플리케이션 프로세스의 생존 응답을 확인하는 용도이며, `/ready` 엔드포인트는 DB 연결 및 EVE 파일 수집 파이프라인의 준비 상태를 점검하는 용도로 동작합니다. 파일 수집 파이프라인이 대기 중이라는 응답만으로 사내 네트워크 전반의 패킷이 누락 없이 관측되고 있다고 판단해서는 안 됩니다.

```bash
curl --fail http://127.0.0.1:38585/ready
docker compose --env-file installation/.env logs --tail=100 netwatcher
```

## 직접 패킷을 캡처하기

자체 패킷 수집 센서를 직접 구동할 때는 설정 파일의 `netwatcher.input.mode` 항목을 `native`로 변경하고 `netwatcher.interface`에 실제 트래픽을 수집할 네트워크 인터페이스명을 명시합니다. 모니터링 대상 네트워크 구간 전체의 패킷을 들여다보려면 스위치 SPAN 포트나 하드웨어 TAP 장비 연결이 필수적으로 선행되어야 합니다. 일반 스위치 포트에 연결하면 다른 호스트 간에 오가는 유니캐스트 트래픽이 센서 인터페이스에 도달하지 않습니다.

Compose 환경을 구성할 때는 사전에 프로젝트의 Python 의존 패키지들을 모두 설치해 둔 환경에서 네이티브 설치 스크립트를 실행해 전용 설정 파일 세트를 생성합니다. 호스트의 Python 런타임 준비 과정은 하단의 [호스트 실행](#호스트에서-직접-실행하기) 안내를 참고합니다. 예시 명령의 `eth0` 부분을 실제 트래픽 수집에 투입할 호스트 인터페이스 식별자로 변경해 실행합니다. 기존 설치가 남아 있다면 충돌을 방지하기 위해 새 디렉터리 경로를 대상 위치로 지정합니다.

```bash
python scripts/install_native.py --interface eth0 --output installation-native
docker compose --env-file installation-native/.env -f docker-compose.yml -f docker-compose.native.yml --profile db up -d --build netwatcher native-sensor
```

서비스가 구동되면 웹 브라우저를 열어 `http://127.0.0.1:38585` 주소로 접속하고, 초기 로그인 비밀번호는 `installation-native/console.env` 파일 안에서 확인합니다. 최초 컨테이너 기동 과정에서는 데이터베이스 계정 생성, 스키마 마이그레이션 적용, 접근 권한 부여 단계가 순차적으로 처리됩니다. 웹 콘솔, 패킷 센서, 마이그레이션 모듈은 최소 권한 원칙에 따라 데이터베이스 계정과 접근 암호를 각각 분리해 배정받습니다. 콘솔과 센서 계정에는 DDL 테이블 생성 권한이 부여되지 않으며, 감사 로그 테이블의 기존 레코드를 임의로 변경하거나 영구 삭제할 수 있는 권한 역시 원천 차단됩니다. 스크립트가 생성한 `.env` 및 일체의 `*.env` 파일은 인증 토큰과 접속 암호가 담긴 보안 자산이므로 파일 접근 권한을 엄격하게 통제하고 외부에 공유하지 않습니다. 웹 콘솔 프로세스는 호스트 패킷 캡처 권한이 없는 비특권 일반 사용자로 동작합니다. 반면 패킷 센서 컨테이너는 호스트 네트워크 스택과 Linux NET_RAW 권한을 부여받아 패킷을 수집하되, 시스템 방화벽 규칙을 조작하는 제어 권한은 배정받지 않습니다. 초기화 서비스는 통신 전용 소켓과 센서 데이터 저장 볼륨을 사전 구축하며, 서비스 재기동 과정에서 관리자 승인을 거쳐 수동 반영된 기존 센서 설정값을 덮어써서 유실시키는 일이 없도록 보장합니다.

Docker를 배제하고 호스트 OS에서 직접 프로세스를 실행하려면 상호 통신을 위한 프로세스 간 소켓 연결 설정을 먼저 구성합니다.

직접 캡처 모드는 패킷 센서와 관리 콘솔을 물리적으로 분리된 별개의 독립 프로세스로 나누어 구동합니다. 센서 설정 파일에는 식별을 위한 `native.sensor_id`와 함께 통신 소켓을 활성화하는 `native.control.enabled: true`를 지정하고, 제어 소켓의 절대 파일 경로인 `native.control.socket_path` 및 통신을 허용할 콘솔 프로세스 사용자의 UID 값인 `native.control.allowed_uid`를 명시합니다. 콘솔 측 설정 파일에도 센서와 일치하는 센서 ID와 소켓 절대 경로를 적어주고, 신뢰할 수 있는 센서 소유자의 UID 값인 `native.control.expected_uid`를 기재합니다. 두 프로세스의 설정 파일 모두 상호 사용자 인증 체계를 활성화하기 위해 `auth.multi_user: true` 옵션을 켜 둡니다.

```bash
python -m netwatcher --component sensor -c sensor.yaml
python -m netwatcher --component console -c console.yaml
```

[호스트 센서·콘솔 설치 안내](NATIVE-SYSTEMD.md) 문서가 제공하는 템플릿 생성 도구와 systemd 유닛 파일을 활용하면 전용 서비스 계정 발급, 통신 소켓 디렉터리 준비, 관측 데이터 저장 경로 생성, 데이터베이스 스키마 초기화 순서를 단일 자동화 흐름으로 묶어 배치할 수 있습니다.

각 구성 요소는 독립적인 systemd 서비스 데몬으로 등록해 격리 실행합니다. 패킷 캡처 특권은 오직 센서 프로세스에만 부여하고, 웹 콘솔 프로세스는 추가 Linux capability가 전혀 없는 일반 사용자 권한으로 격리해 구동합니다. 콘솔은 패킷 드라이버에 직접 개입하지 않고 유닉스 도메인 소켓과 디스크에 영속화된 관측 데이터만을 조회합니다. 설정에서 `native.console.separate` 키를 명시하지 않더라도 시스템은 항상 콘솔을 센서와 분리된 단독 프로세스로 실행하며, 설정을 `false`로 강제해 단일 프로세스로 합쳐서 띄우는 동작은 소프트웨어 차원에서 지원하지 않습니다.

센서 소켓이 위치하는 파일시스템 디렉터리는 센서 프로세스 계정이 소유해야 하며, 권한 없는 다른 일반 계정에 쓰기 권한이 열려 있어서는 안 됩니다. 콘솔과 센서를 서로 다른 시스템 사용자 계정으로 격리 구동할 경우에는 `native.control.socket_gid` 항목에 두 계정이 함께 소속된 공용 그룹의 GID를 설정하고 해당 디렉터리에 그룹 진입 권한을 열어줍니다. 센서 프로세스는 제어 소켓을 통해 변경 요청이 들어올 때마다 소켓 파일의 소유권 상태와 호출자의 계정 권한을 먼저 검증한 뒤 유효한 명령만 처리합니다.

## 호스트에서 직접 실행하기

Python 3.12 이상 버전과 네트워크 통신이 가능한 PostgreSQL 데이터베이스 인스턴스를 준비합니다. 설정 파일 내 DB 접속 호스트 주소와 Suricata EVE 로그 파일 경로는 Docker 내부 호스트가 아닌 현재 호스트 OS 관점에서 유효하게 접근할 수 있는 경로와 주소로 기재합니다. Docker Compose 환경을 전제로 작성된 기본 호스트명 `db`나 컨테이너 전용 로그 마운트 디렉터리 경로를 호스트 구성에 그대로 대입하지 않도록 유의합니다.

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m netwatcher -c config/default.yaml
```

Suricata 로그를 수신하는 EVE 모드 구동 시에는 프로세스 실행에 `sudo` 관리자 권한이 요구되지 않습니다. 호스트 데몬 등록은 [EVE systemd 안내](EVE.md#systemd) 문서와 저장소 내 `deploy/panopticon-eve.service` 템플릿을 활용해 등록합니다. EVE 파싱 대신 네이티브 패킷 수집 방식을 선택하는 환경이라면 호스트에 libpcap 라이브러리를 설치하고 인터페이스 패킷 캡처 권한을 서비스 계정에 부여하는 사전 작업을 별도로 진행합니다.

## 호스트 에이전트 설치

Panopticon Agent는 Linux `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/loadavg`, `/proc/meminfo`, `/proc/self/status`에서 TCP 소켓과 부하·메모리 지표를 수집하는 Rust 단일 바이너리입니다. Rust 런타임 설치는 필요 없습니다. 5초 간격으로 하트비트와 연결 상태 변경을 전송하며, 샘플링은 간격당 최대 256개·리스닝 소켓 제외입니다. 로컬 release 빌드는 1,674,960바이트(약 1.6MiB)이며 플랫폼·빌드에 따라 크기는 달라질 수 있습니다.

대상은 x86_64 또는 aarch64 Linux이고 systemd가 실행 중이어야 합니다. 콘솔은 HTTPS로 접근할 수 있어야 하며 HTTP는 개발용 loopback 주소만 허용합니다. 먼저 콘솔 프로세스 환경에 `PANOPTICON_ENROLLMENT_TOKEN`을 설정하고 시작합니다. 토큰은 16~512자의 URL-safe 문자열이며 게이트웨이 최초 등록부터 15분간·호스트 한 대에만 사용합니다. 다음 호스트에는 새 토큰을 설정하고 콘솔을 재시작해야 합니다.

대상 호스트에서 루트 셸을 열고 콘솔 주소, 바이너리 URL, 신뢰된 경로에서 받은 SHA-256을 설정합니다. 등록 토큰은 화면에 표시하지 않고 입력합니다.

```bash
sudo -i
cd /home/nirna/jobs/panopticon
export PANOPTICON_CONSOLE_URL='https://console.example'
read -r -s -p 'Enrollment token: ' PANOPTICON_ENROLLMENT_TOKEN
export PANOPTICON_ENROLLMENT_TOKEN
export PANOPTICON_AGENT_BINARY_URL='https://artifacts.example/linux-x86_64/panopticon-agent'
export PANOPTICON_AGENT_SHA256='<신뢰된 64자리 SHA-256>'
bash scripts/agent/install.sh
```

작업 경로와 아키텍처별 바이너리 URL은 실제 배포 환경으로 바꿉니다. 바이너리를 직접 빌드했다면 `cargo build --release --manifest-path agent/Cargo.toml`로 생성한 실행 파일 경로를 `PANOPTICON_AGENT_BINARY`에 지정합니다. 이 경우 다운로드 URL·체크섬 환경변수 대신 로컬 파일을 사용합니다.

검증한 설치 스크립트를 별도 HTTPS 호스트에 배포한 경우 같은 루트 셸의 환경변수로 원라인 설치할 수 있습니다.

```bash
curl -fsSL https://<artifact-host>/install.sh | bash
```

현재 저장소는 콘솔의 `/install.sh`나 바이너리 배포 엔드포인트를 제공하지 않습니다. 설치기는 환경변수를 사용하며 `bash -s -- --token <token>` 인자 형식은 지원하지 않습니다. HTTPS 배포 주소와 바이너리 체크섬을 먼저 준비해야 합니다.

설치기는 바이너리를 `/usr/local/bin/panopticon-agent`에 배치하고 DynamicUser systemd 서비스를 등록합니다. 환경 파일 `/etc/panopticon-agent/agent.env`는 0600, 상태 디렉터리는 `/var/lib/panopticon-agent`입니다. `MemoryHigh=15M`는 메모리 압력 제어 설정이며 실제 RSS나 강제 상한을 뜻하지 않습니다.

```bash
systemctl status panopticon-agent
journalctl -u panopticon-agent
```

게이트웨이의 등록·서명 인증과 순차 배치 규칙은 [에이전트 API](API.md#에이전트-게이트웨이)를 참고하십시오. 재시작 시 기존 자격 증명과 시퀀스를 재사용합니다. 미전송 배치 하나를 fsync와 원자적 저장으로 보존하며 전달될 때까지 새 소켓 샘플링을 멈춥니다. 전체 오프라인 WAL이 아니므로 단절 중 모든 연결 이력을 보존하지 않습니다. Netlink/eBPF, mTLS, 에이전트 침묵 경보와 원격 호스트 격리는 후속 계획입니다.

## 기존 설치 업데이트하기

운영체제 환경 업데이트를 진행하기 전에 [DB·설정·증거 백업](OPERATIONS-GUIDE.md#백업) 절차에 따라 전체 데이터베이스 덤프와 설정 파일, 증거 아카이브를 온전히 백업하고 릴리스 변경 기록의 버전 간 호환성 주의사항을 검토합니다. 이전 설정 파일에서 입력 모드 옵션을 생략한 채 운영해 왔다면 패킷 직접 캡처 모드가 기본 동작으로 유지됩니다. 새로 배포된 기본 설정 템플릿은 EVE 모드를 기준으로 작성되어 있으므로, 기존에 사용 중이던 운영 설정 파일을 최신 템플릿 파일로 무단 덮어쓰지 않도록 주의합니다.

새로운 환경 설정을 생성하는 초기화 도구를 기존 데이터베이스의 비밀번호나 접속 자격증명을 임의로 갱신하는 목적으로 실행해서는 안 됩니다. 기존 환경에서 사용하던 서비스 계정, JWT 인증 키, 데이터베이스 연결 정보, 관측 자료 저장 볼륨을 온전히 유지한 상태에서, 새 릴리스의 소스 코드가 위치한 디렉터리로 이동해 실행 중인 서비스를 안전하게 내린 뒤 스키마 마이그레이션을 순서대로 적용합니다.

```bash
docker compose stop netwatcher
docker compose --profile migrate run --rm --build db-migrate
```

네이티브 직접 캡처 센서를 계속 운용하는 시스템이라면 Compose 실행 시 `docker-compose.native.yml` 파일을 명령어 매개변수에 함께 지정하여 컨테이너들을 시작합니다. Suricata EVE 기반 수집 파이프라인으로 전환할 때는 호스트 로그 파일의 연결 경로를 점검하고, 일반 사용자 권한으로 격리된 컨테이너가 기존 볼륨 디렉터리 내 로그 저장 경로에 정상적으로 쓰기 작업을 수행할 수 있는지 권한을 확인해야 합니다. 파일시스템의 파일 소유권은 백업을 안전하게 마친 뒤 실제 필요한 최소한의 디렉터리 범위에 한해서만 제한적으로 수정합니다. 시스템 내 다른 컨테이너 서비스들이 공유하고 있는 데이터 볼륨까지 일괄적으로 파일 소유권을 수정하지 않습니다.

서비스의 준비 완료 응답을 확인하고 이전에 수집된 사건 기록, 감시 대상 장치 목록, 감사 로그가 정상적으로 조회되는지 점검한 뒤 실제 운영 트래픽 수집을 재개합니다. 생성해 둔 백업 아카이브는 업데이트 후 전체 시스템의 정상 작동이 최종적으로 검증될 때까지 폐기하지 않고 보관합니다. 이전 애플리케이션 버전으로 롤백해야 할 때는 하위 DB 스키마 간의 데이터 호환성을 먼저 확인하며, 마이그레이션 다운그레이드가 지원되지 않는 비가역적 스키마 변경이 포함되어 있다면 앞서 받아 둔 DB 전체 백업본을 복원해 복구합니다.

### 분리 센서 설치 업데이트

`install_native.py` 스크립트로 구축한 환경은 기존 설정 파일, 서비스 비밀번호, 데이터 영속 볼륨을 그대로 보존하며 업데이트를 진행합니다. 전체 데이터 백업을 완료한 후 새로 내려받은 릴리스 소스 디렉터리로 이동하여 아래의 컨테이너 업데이트 명령들을 순차적으로 실행합니다. 데이터베이스 사용자 계정 생성은 최초 시스템 설치 단계에서 한 번만 수행되는 작업이므로, 버전 업데이트 단계에서는 스키마 마이그레이션과 테이블 접근 권한 부여 단계만 다시 호출합니다.

```bash
docker compose --env-file installation-native/.env -f docker-compose.yml -f docker-compose.native.yml --profile db stop netwatcher native-sensor
docker compose --env-file installation-native/.env -f docker-compose.yml -f docker-compose.native.yml --profile db run --rm --no-deps --build db-migrate
docker compose --env-file installation-native/.env -f docker-compose.yml -f docker-compose.native.yml --profile db run --rm --no-deps --build native-db-grants
docker compose --env-file installation-native/.env -f docker-compose.yml -f docker-compose.native.yml --profile db up -d --build netwatcher native-sensor
```

서비스 기동 후 웹 대시보드 로그인 가능 여부, 원격 센서와의 소켓 연결 상태, 이전 보안 사건 목록의 정상 노출, 감사 로그 기록 조회를 차례로 점검합니다. 위 업데이트 절차는 `console.env`, `sensor.env`, `migrate.env`, `grants.env` 환경 파일이 디렉터리 내에 개별적으로 분리 보관된 다중 계정 분리 설치 환경을 기준으로 적용합니다. 과거 배포본의 단일 계정 통합 구성 방식을 이러한 다중 계정 분리 구성으로 전환하려면 데이터 마이그레이션 및 권한 재할당을 위한 별도의 이전 절차를 사전에 준비해야 합니다.

## 설치 문제 해결

- **EVE 파일을 읽지 못함:** 지정한 경로의 유효성, 심볼릭 링크가 아닌 일반 파일 여부, 실행 계정의 그룹 읽기 권한 및 상위 디렉터리 실행(탐색) 권한을 확인합니다.
- **DB 연결 실패:** 컨테이너 내부에서 도달 가능한 DB 호스트 주소와 포트, 데이터베이스 계정명, pg_hba.conf 등 접속 허용 설정을 확인합니다.
- **저장 한도 도달:** 관측 범위 관리 화면에서 보존 기록 통계와 디스크 용량 할당량을 확인하고 보존 기간과 최대 보존 용량 설정을 완화합니다.
- **로그인 실패:** 초기 설치 설정 생성 시 `installation/.env` 등에 기록된 관리자 자격증명과 로그인 연속 실패 차단 정책을 확인합니다.
- **설정을 저장할 수 없음:** 기본 구성에서 설정 디렉터리 볼륨은 읽기 전용으로 안전하게 마운트됩니다. 설정을 콘솔에서 갱신하려면 [설정 쓰기 허용](CONFIGURATION.md#대시보드에서-설정-저장) 가이드를 참고하여 쓰기 마운트로 전환합니다.
