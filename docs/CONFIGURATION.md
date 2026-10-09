# 설정 가이드

설정 파일은 YAML이고 모든 키는 `netwatcher:` 아래에 둡니다. 비밀번호와 토큰은 YAML이 아니라 `.env`나 서비스 환경변수에 둡니다.

```bash
python -m netwatcher -c config/default.yaml
```

| 설정 원천 | 우선순위 |
| --- | --- |
| 환경변수 (DB, 로그인, 알림 등 정해진 키) | 높음 |
| `-c` 또는 `NETWATCHER_CONFIG`로 지정한 YAML | 중간 |
| `config/default.yaml` | 기본 |

대시보드에서 바꾸는 엔진 설정은 엔진이 선언한 키와 타입만 받고 나머지는 거절합니다. `input.eve.sources`처럼 목록 형식인 값은 환경변수로 지정할 수 없습니다. 전체 키 목록은 [기본 설정 파일](../config/default.yaml)에 있습니다.

## 기본 운영 설정

기존 파일의 해당 블록만 고칩니다. 아래 예시로 파일 전체를 덮어쓰지 않습니다.

```yaml
netwatcher:
  interface: eth0          # 직접 캡처 시 실제 인터페이스 이름
  workers: 1
  support:
    profile: limited
  web:
    host: 127.0.0.1
    port: 38585
  response:
    enabled: false         # 자동 차단 끔
```

`bpf_filter`로 캡처 트래픽을 미리 거를 수 있습니다. 걸러진 트래픽은 탐지에서 완전히 빠집니다.

## 인증과 HTTPS

`.env`에 다음을 넣습니다.

```dotenv
NETWATCHER_LOGIN_ENABLED=true
NETWATCHER_LOGIN_USERNAME=admin
NETWATCHER_LOGIN_PASSWORD=<초기 비밀번호>
NETWATCHER_JWT_SECRET=<32바이트 이상 고정 값>
```

`NETWATCHER_JWT_SECRET`을 비워 두면 시작할 때마다 새로 만들어져 재시작 때 모든 로그인이 풀립니다.

### 개인 계정

기본은 설정 파일의 관리자 계정 하나입니다. 개인별 계정과 역할을 쓰려면:

```yaml
netwatcher:
  auth:
    enabled: true
    multi_user: true
    username: admin
```

- 계정 테이블이 비어 있을 때만 `NETWATCHER_LOGIN_PASSWORD`로 초기 관리자를 만듭니다. 이후 비밀번호를 바꿔도 재시작 때 되돌아가지 않습니다.
- 계정은 콘솔의 **계정** 메뉴에서 관리합니다. 역할·활성 상태·비밀번호를 바꾸면 그 계정의 로그인이 풀립니다.
- 마지막 남은 활성 관리자는 비활성화하거나 역할을 내릴 수 없습니다.

| 역할 | 할 수 있는 일 |
| --- | --- |
| viewer | 조회, 내보내기 |
| analyst | viewer + 분석, 설정 제안 |
| admin | analyst + 계정·설정·승인·판정·차단 관리 |

### 외부 접속과 HTTPS

다른 장치에서 접속하게 하려면 `web.host`를 열고 인증을 반드시 켭니다. HTTPS는 리버스 프록시에 맡기거나 내장 TLS를 씁니다.

```yaml
netwatcher:
  web:
    host: 0.0.0.0
    tls:
      enabled: true
      certfile: /etc/panopticon/server.crt
      keyfile: /etc/panopticon/server.key
```

컨테이너에서는 인증서를 읽기 전용으로 마운트합니다. 리버스 프록시를 쓰면 `trusted_proxies`와 `cors.allowed_origins`에 실제 프록시와 서비스 주소만 넣습니다.

## 조직 계정으로 로그인

OIDC 공급자의 조직 계정으로 로그인할 수 있습니다. 조건은 다음과 같습니다.

- `auth.multi_user: true`
- 콘솔이 HTTPS로 서비스됨
- `NETWATCHER_JWT_SECRET`이 32바이트 이상
- 공급자가 Authorization Code, PKCE S256, RS256을 지원

공급자에 콜백 주소를 등록하고 설정합니다.

```yaml
netwatcher:
  auth:
    enabled: true
    multi_user: true
    oidc:
      enabled: true
      issuer: https://login.example.org/realms/security
      client_id: panopticon
      redirect_uri: https://panopticon.example.org/api/auth/oidc/callback
      endpoint_origins: []
```

- 클라이언트 비밀값이 있으면 `NETWATCHER_OIDC_CLIENT_SECRET`에 넣습니다(`client_secret_basic`). 없으면 공급자가 `none` 인증을 지원해야 합니다.
- 인증·토큰·공개 키 엔드포인트의 도메인이 발급자와 다르면 그 도메인을 `endpoint_origins`에 추가합니다. 경로 없이 `https://keys.example.org` 형식입니다.
- 사설 CA는 시스템 신뢰 저장소에 등록하거나 `SSL_CERT_FILE`로 지정합니다.

계정 연결은 **계정 → 사용자 → 조직 계정 연결**에서 발급자(`iss`)와 사용자 ID(`sub`)를 입력합니다. 연결된 사용자는 로그인 화면의 **조직 계정으로 로그인**을 쓸 수 있고, 권한은 내부 계정의 역할을 따릅니다. 연결되지 않았거나 비활성화된 계정은 로그인할 수 없습니다.

## 대시보드에서 설정 저장

Docker 기본 구성은 `config` 디렉터리를 읽기 전용으로 마운트합니다. 탐지는 동작하지만 대시보드에서 바꾼 엔진 설정이나 예외 목록은 저장되지 않습니다.

저장하려면 쓰기 가능한 설정 디렉터리를 따로 만들어 연결합니다.

```bash
mkdir -p config-write
cp -a config/. config-write/
export NETWATCHER_WRITABLE_CONFIG_DIR="$(pwd)/config-write"
docker compose -f docker-compose.yml -f docker-compose.config-write.yml up -d netwatcher
```

- 서비스 계정이 이 디렉터리에 파일을 쓸 수 있어야 합니다.
- 쓰기는 임시 파일 → fsync → 이름 바꾸기 순서라 중간에 실패해도 기존 파일이 남습니다.
- HTTP 200이어도 응답에 `applied=false`가 있으면 반영되지 않은 것입니다.
- 한 설정 파일을 여러 프로세스가 동시에 고치면 서로의 변경을 모릅니다. 한 프로세스만 쓰게 합니다.

## 테넌트

```yaml
netwatcher:
  postgresql:
    tenant_id: "00000000-0000-0000-0000-000000000000"   # 기본값
```

`events`, `devices`, `incidents`, `audit_log`에는 RLS가 걸려 있습니다. 콘솔·센서 DB 연결은 접속할 때 이 값을 테넌트 컨텍스트로 지정하므로, 테이블 소유자가 아닌 계정을 쓰는 역할 분리 설치에서도 데이터를 읽고 씁니다. 키를 생략하면 0 테넌트를 씁니다. 빈 값(`""`)은 기본 컨텍스트를 끕니다. `system`은 지정할 수 없습니다.

## 저장과 보존

| 설정 | 기본값 | 용도 |
| --- | --- | --- |
| `retention.events_days` | 90일 | 사건 |
| `retention.traffic_stats_days` | 365일 | 트래픽 통계 |
| `retention.incidents_days` | 180일 | 관련 사건 묶음 |
| `evidence.buffer_bytes` | 8MiB | 패킷 증거 메모리 버퍼 |
| `evidence.queue_jobs` | 32건 | 증거 작업 대기 |
| `evidence.queue_bytes` | 8MiB | 증거 작업 데이터 |
| `evidence.cooldown_seconds` | 60초 | 같은 조건의 증거 수집 간격 |
| `evidence.max_storage_mb` | 500 | 증거 디스크 용량 |
| `evidence.max_files` | 10,000개 | 증거 파일 수 |
| `threatfeeds.cache_dir` | `XDG_CACHE_HOME/threatfeeds`, 없으면 `data/threatfeeds` | 위협 피드 캐시 |

EVE 입력의 보존 한도는 따로 있습니다([EVE 연결](EVE.md#보존-한도)). 검토 보존으로 고정한 증거는 자동 정리에서 빠지며 최대 64파일·32MiB·24시간입니다.

## DB 장애 복구 파일

DB에 저장하지 못한 사건을 디스크에 잠시 보관했다가 재시작이나 DB 복구 때 다시 저장합니다. 기본값은 꺼짐입니다.

```yaml
netwatcher:
  storage:
    recovery_spool:
      enabled: true
      directory: data/recovery
      event_bytes: 16777216      # 16MiB
      event_files: 64
      ttl_seconds: 300
```

- 디렉터리는 서비스 계정만 접근하게 하고 한 인스턴스만 마운트합니다.
- systemd처럼 작업 디렉터리가 읽기 전용인 환경에서는 `directory`에 쓰기 가능한 절대경로를 적습니다.
- 통계와 장치 메타데이터는 복구 대상이 아닙니다.

운영 절차는 [DB 장애와 복구](OPERATIONS-GUIDE.md#db-장애와-복구)를 봅니다.

## 선택 기능

| 기능 | 켜는 방법 | 주의 |
| --- | --- | --- |
| 알림 | `.env`에 채널 접속 정보, `alerts.channels`에서 채널 활성화 | 값이 빠지면 알림 상태 패널에 오류 표시 |
| NetFlow/IPFIX | `netflow.enabled: true`, 수신 주소·포트 지정 | 패킷 본문은 받지 않음 |
| AI 분석 | 외부 CLI 설치, `ai_analyzer.enabled: true`, `apply_mode: propose` | 외부로 나가는 자료 범위를 먼저 검토 |
| API 문서 | `web.enable_docs: true` | `/docs`, `/openapi.json` 노출 |

### NetFlow

분리 센서에서 NetFlow를 받으려면 `config/sensor.yaml`의 `netflow.enabled`를 켜고 라우터가 센서의 수신 포트로 보내게 합니다.

- `netflow.host`는 센서가 수신할 로컬 주소입니다(라우터 주소가 아님).
- 방화벽에서 허용한 라우터만 해당 UDP 포트에 닿게 합니다.
- 엔진 옵션은 `netflow.engines.flow_port_scan`, `netflow.engines.flow_data_exfil`입니다. 이름이 비슷한 패킷 엔진 설정과 다릅니다.

## 지원 범위

`support.profile`이 지원하지 않는 구성을 시작 단계에서 거절합니다.

| 항목 | `limited` (기본) |
| --- | --- |
| 센서·워커 | 단일 센서, 단일 워커 |
| 고가용성(HA) | 거절 |
| AI | 제안 모드만 |
| 방화벽 차단 | iptables만, 기본 꺼짐 |
| nftables 차단 | 모든 프로필에서 거절 |

`full` 프로필로 바꿔도 구현되지 않은 기능이 생기지는 않습니다. 실험 단계인 ML 모듈은 탐지 엔진 목록에 등록되지 않습니다. iptables 차단을 켜기 전에 트래픽 경로, 승인, 규칙 만료, 되돌리기 절차를 확인합니다.
