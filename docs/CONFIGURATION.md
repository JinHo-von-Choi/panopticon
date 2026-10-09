# 설정 가이드

기본 설정 파일은 `config/default.yaml`입니다. 모든 설정은 `netwatcher:` 아래에 작성해야 하며 접속 비밀번호와 토큰은 `.env`나 서비스 환경변수에 따로 보관합니다.

```bash
python -m netwatcher -c config/default.yaml
```

다른 파일을 지정할 때는 `-c` 옵션을 넘기거나 `NETWATCHER_CONFIG` 환경변수를 선언하십시오. 환경변수로 지정한 DB·로그인·알림 값은 YAML 파일에 적힌 내용보다 항상 우선합니다.

## 기본 운영 설정

아래 설정값은 기존 파일의 해당 블록에 맞춰 반영합니다. 이 예시로 전체 파일을 덮어쓰면 안 됩니다.

```yaml
netwatcher:
  interface: eth0
  workers: 1
  support:
    profile: limited
  web:
    host: 127.0.0.1
    port: 38585
  response:
    enabled: false
```

`eth0` 자리에는 서버의 실제 네트워크 인터페이스 이름을 적습니다. `bpf_filter`로 들어오는 트래픽을 미리 걸러낼 수 있으나, 필터링으로 제외된 통신은 탐지 대상에서 완전히 빠집니다.

ML 기능과 Redis 기반 HA는 현재 실험 단계입니다. ML은 기본 탐지 엔진 목록에 등록되지 않고, HA 역시 기본 `limited` 프로필 상태에서는 동작하지 않습니다. 체크포인트를 Redis에 저장하도록 두더라도 `ha.enabled=false`로 남아 있으면 리더 선출 절차를 밟지 않습니다. 운영 환경에서는 단일 센서와 단일 워커 구성을 유지하십시오.

## 인증과 HTTPS

`.env` 파일에 `NETWATCHER_LOGIN_ENABLED=true`, 관리자 로그인 계정 및 비밀번호, 그리고 `NETWATCHER_JWT_SECRET`를 선언합니다. 프로세스를 재시작해도 기존 로그인 세션이 끊기지 않으려면 서명 키가 변하지 않아야 합니다.

기본 환경은 설정 파일에 등록된 관리자 단일 계정만 처리합니다. 다중 사용자와 개별 역할을 분리해서 운영하려면 인증 기능을 켜고 `auth.multi_user=true`를 명시합니다.

```yaml
netwatcher:
  auth:
    enabled: true
    multi_user: true
    username: admin
```

최초 구동 시에는 `NETWATCHER_LOGIN_PASSWORD`로 초기 비밀번호를 지정하고 `NETWATCHER_JWT_SECRET`로 서명 키를 등록합니다. 계정 테이블이 비어 있을 때만 이 초기 계정을 생성하므로, 이후에 비밀번호를 바꾸더라도 컨테이너가 다시 뜰 때 이전 값으로 되돌아가지 않습니다.

관리자는 웹 콘솔의 **계정** 메뉴에서 작업합니다. 여기서 새 사용자를 등록하고 역할, 활성화 여부, 비밀번호를 수정할 수 있습니다. 사용자 정보를 수정하면 해당 계정의 접속 세션은 즉시 끊어집니다. 마지막 남은 활성 관리자 계정은 비활성화하거나 일반 역할로 내릴 수 없습니다. 사용자 데이터는 PostgreSQL에 보관되므로 버전을 올리기 전에 데이터베이스를 백업하십시오.

외부 장비에서 콘솔에 접속하게 하려면 `web.host`를 해당 인터페이스 주소로 열고 인증을 활성화합니다. HTTPS 암호화는 전면 리버스 프록시로 넘기거나 애플리케이션의 자체 TLS 옵션을 직접 구성합니다.

```yaml
netwatcher:
  web:
    host: 0.0.0.0
    tls:
      enabled: true
      certfile: /etc/panopticon/server.crt
      keyfile: /etc/panopticon/server.key
```

인증서와 개인키 경로는 실제 서버의 파일 위치로 수정하고 컨테이너 배포 시에는 읽기 전용으로 볼륨을 연결합니다. 전면에 리버스 프록시를 배치했다면 `trusted_proxies`와 `cors.allowed_origins`에 실제 경유 프록시와 웹 서비스 주소만 등록하십시오.

## 조직 계정으로 로그인

외부 OIDC 공급자에 연동된 조직 계정으로도 콘솔 로그인을 지원합니다. 이 방식을 쓰려면 다중 사용자 인증을 활성화하고 웹 콘솔을 반드시 HTTPS로 서비스해야 합니다. `NETWATCHER_JWT_SECRET` 항목에는 32바이트 이상 길이의 고정 서명 키를 넣어야 합니다.

연동할 공급자에 Authorization Code, PKCE S256, RS256 방식과 아래 콜백 주소를 등록한 다음 설정을 진행합니다. 예시 주소와 클라이언트 ID는 실제 값으로 변경하십시오.

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

공급자 측에서 클라이언트 보안 비밀번호를 발급했다면 `NETWATCHER_OIDC_CLIENT_SECRET` 환경변수에 입력하십시오. 이 설정이 들어가면 `client_secret_basic` 인증 규격을 사용합니다. 비밀값이 따로 없는 공개 클라이언트 환경은 공급자가 `none` 인증을 지원해야 합니다. OIDC 공급자의 메타데이터 문서에 PKCE S256과 RS256 규격이 명시되어 있어야 정상 작동합니다.

인증·토큰·공개 키 엔드포인트 도메인이 공급자 발급자 주소와 다르면 해당 HTTPS 도메인만 `endpoint_origins`에 추가합니다. `https://keys.example.org`처럼 경로를 제외한 도메인 주소만 적어야 합니다. 사내 사설 CA 인증서는 시스템 기본 신뢰 저장소에 등록하거나 프로세스 환경변수 `SSL_CERT_FILE`로 지정하십시오.

관리자는 **계정 → 해당 사용자 → 조직 계정 연결** 화면으로 이동합니다. 여기서 발급자 주소(`iss`)와 사용자 고유 ID(`sub`)를 기입하여 맵핑합니다. 맵핑이 끝나면 해당 사용자는 로그인 페이지에서 **조직 계정으로 로그인** 버튼으로 접속할 수 있습니다. 시스템 권한은 내부 계정에 부여된 역할을 그대로 이어받으며, 연동되지 않았거나 비활성화된 계정은 인증을 통과할 수 없습니다.

## 대시보드에서 설정 저장

Docker 기본 배포판은 `config` 디렉터리를 읽기 전용으로 마운트합니다. 모니터링과 탐지는 바로 돌아가지만 대시보드에서 룰셋이나 허용 목록을 수정해도 디스크에 쓰지 못합니다.

웹 콘솔에서 설정 변경을 저장해야 한다면 별도 디렉터리를 만들어 기본 설정을 복사한 뒤 `NETWATCHER_WRITABLE_CONFIG_DIR`에 해당 절대 경로를 지정하십시오. 서비스 실행 계정이 이 디렉터리 안의 파일을 수정하고 새로 쓸 수 있는 권한을 갖고 있어야 합니다.

```bash
mkdir -p config-write
cp -a config/. config-write/
export NETWATCHER_WRITABLE_CONFIG_DIR="$(pwd)/config-write"
docker compose -f docker-compose.yml -f docker-compose.config-write.yml up -d netwatcher
```

PostgreSQL 스키마를 최신 버전까지 마이그레이션한 다음 실행하십시오. 파일 쓰기가 실패하면 기존 설정은 그대로 유지됩니다. HTTP 성공 응답 코드만 보지 말고 변경 사항이 실제 반영되었는지 함께 확인해야 합니다.

## 저장과 보존

| 설정 | 기본값 | 용도 |
| --- | --- | --- |
| `retention.events_days` | 90일 | 사건 보존 기간 |
| `retention.traffic_stats_days` | 365일 | 트래픽 통계 보존 기간 |
| `retention.incidents_days` | 180일 | 관련 사건 묶음 보존 기간 |
| `evidence.buffer_bytes` | 8 MiB | 패킷 증거 메모리 버퍼 상한 |
| `evidence.queue_jobs` | 32건 | 실행·대기 중 증거 작업 상한 |
| `evidence.queue_bytes` | 8 MiB | 증거 작업 데이터 상한 |
| `evidence.cooldown_seconds` | 60초 | 같은 조건의 증거 수집 간격 |
| `evidence.max_storage_mb` | 500 | 증거 저장 용량 상한 |
| `evidence.max_files` | 10,000개 | 증거 파일 수 상한 |

보안 사건이나 통계의 데이터 보존 기간과 증거 패킷 파일의 디스크 용량 한도는 완전히 별개의 기준입니다. 검토를 위해 락이 걸린 패킷 덤프는 자동 정리 작업에서 제외되며, 보존 한도는 최대 64파일·32 MiB·24시간으로 묶여 있습니다.

## DB 장애 복구 파일

데이터베이스에 정상 기록되지 않은 보안 사건을 프로세스 재시작 시 복구하려면 아래 기능을 활성화합니다. 기본값은 비활성화 상태입니다.

```yaml
netwatcher:
  storage:
    recovery_spool:
      enabled: true
      directory: data/recovery
      event_bytes: 16777216
      event_files: 64
      ttl_seconds: 300
```

스풀 용량 한도는 16 MiB·64파일·300초입니다. 이 복구 디렉터리는 서비스 전용 계정만 접근할 수 있게 제한하고 반드시 단일 인스턴스에서만 마운트해야 합니다. 집계 통계와 감지 장비 메타데이터는 이 스풀 복구 대상에 들어가지 않습니다. 구체적인 작업 방식은 [운영 가이드](OPERATIONS-GUIDE.md#db-장애와-복구) 문서를 확인하십시오.

## 선택 기능

- **알림:** `.env` 파일에 연동할 채널 접속 정보만 기입하고 `alerts.channels`에서 대상 채널을 켭니다. 파라미터가 빠졌거나 오탈자가 있으면 알림 채널 상태 패널에 오류가 출력됩니다.
- **NetFlow/IPFIX:** 라우터 장비에서 flow 데이터를 전달할 수 있다면 `netflow.enabled`를 켜고 수신 IP와 포트를 바인딩합니다. 패킷 페이로드 원문을 덤프하는 기능은 아닙니다.

독립 센서에서 NetFlow를 함께 수신하려면 최초 구동 전에 `config/sensor.yaml` 파일의 `netflow.enabled`를 `true`로 바꾼 뒤 네트워크 라우터가 센서의 수신 포트로 flow 패킷을 쏘도록 설정하십시오. `netflow.host`는 라우터 주소가 아니라 센서 프로세스가 패킷을 받을 바인딩 인터페이스 주소입니다. 상단 방화벽에서 인가된 라우터 IP만 해당 UDP 포트로 들어오도록 막아야 합니다.

NetFlow 분석 엔진 세부 옵션은 `netflow.engines.flow_port_scan`과 `netflow.engines.flow_data_exfil` 항목에서 제어합니다. 데몬이 올라간 뒤에는 웹 콘솔의 엔진 설정 화면에서 탐지 임계치와 룰 활성화 상태를 바꿀 수 있습니다. 파라미터를 고쳤다면 감사 로그와 반영 상태를 점검하십시오. 여기서 저장한 값은 데몬이 재시작되어도 유지됩니다. 이름이 같은 일반 패킷 엔진 설정과 혼동해서 수정하지 않도록 주의하십시오.
- **AI 분석:** 연동할 외부 CLI 도구를 세팅하고 `ai_analyzer.enabled=true`를 켭니다. 자동 차단 오동작을 방지하려면 `apply_mode`를 `propose`로 고정하십시오. 외부 모델로 유출될 수 있는 데이터 목록과 전송 범위를 먼저 검토해야 합니다.
- **API 문서:** `web.enable_docs=true`로 활성화하면 `/docs` 경로와 `/openapi.json` 스펙을 외부에 노출합니다. 폐쇄망 운영 환경이라서 외부 열람이 필요 없다면 기본값인 `false`를 그대로 두는 편이 안전합니다.

## 지원 범위

기본 `limited` 프로필은 단일 센서와 단일 워커 전용으로 묶여 있으며 고가용성 클러스터링은 꺼지고 AI는 제안 모드로만 동작합니다. 프로필을 `full`로 올린다고 해서 코드에 없는 미구현 기능이 살아나는 것은 아닙니다.

nftables 기반 자동 차단 기능은 구동 단계에서 즉시 거부됩니다. 다중 워커 구성과 고가용성 기능 역시 기본 `limited` 모드에서는 실행할 수 없습니다. 시스템 레벨에서 실제 동작하는 방화벽 인터페이스는 iptables뿐이며 이마저도 기본값은 꺼져 있습니다. 이를 켜기 전에는 패킷이 지나가는 트래픽 경로와 차단 승인, 규칙 만료, 롤백 절차를 사전에 검증하십시오.

전체 설정 항목은 [기본 설정 파일](../config/default.yaml)을 참고하세요.