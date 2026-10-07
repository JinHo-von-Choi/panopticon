# 설정 가이드

기본 설정 파일은 `config/default.yaml`입니다. 설정은 `netwatcher:` 아래에 작성합니다. 접속 비밀번호와 토큰은 `.env` 또는 서비스 환경변수에 둡니다.

```bash
python -m netwatcher -c config/default.yaml
```

다른 파일을 사용하려면 `-c`로 경로를 지정하거나 `NETWATCHER_CONFIG`를 설정합니다. 환경변수로 지정한 DB·로그인·알림 값은 YAML보다 우선합니다.

## 기본 운영 설정

아래 값은 기존 설정 파일의 해당 항목에 적용합니다. 이 예시만으로 전체 파일을 대체하지 마세요.

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

`eth0`는 실제 인터페이스 이름으로 바꿉니다. `bpf_filter`로 입력을 제한할 수 있지만, 필터로 제외한 통신은 분석하지 않습니다.

## 인증과 HTTPS

`.env`에 `NETWATCHER_LOGIN_ENABLED=true`, 로그인 계정·비밀번호와 `NETWATCHER_JWT_SECRET`를 설정합니다. 서명 키를 유지해야 재시작 후 기존 로그인 토큰도 유지됩니다.

기본 로그인은 관리자 한 계정을 사용합니다. API에는 조회·분석·관리자 역할 구분이 있지만, 여러 사용자의 계정을 발급·관리하는 로그인 기능은 지원하지 않습니다.

다른 장치에 직접 공개하려면 `web.host`를 해당 주소로 바꾸고 인증을 활성화합니다. HTTPS는 리버스 프록시에서 처리하거나 앱의 TLS 설정으로 제공할 수 있습니다.

```yaml
netwatcher:
  web:
    host: 0.0.0.0
    tls:
      enabled: true
      certfile: /etc/panopticon/server.crt
      keyfile: /etc/panopticon/server.key
```

인증서와 개인키 경로는 실제 파일로 바꾸고, 컨테이너 배포에서는 해당 경로에 읽기 전용으로 마운트합니다. 리버스 프록시를 사용한다면 `trusted_proxies`와 `cors.allowed_origins`를 실제 프록시 주소와 웹 주소로 제한합니다.

## 대시보드에서 설정 저장

기본 Docker 배포의 `config` 마운트는 읽기 전용입니다. 조회와 탐지는 가능하지만 설정·허용 목록 변경은 저장할 수 없습니다.

쓰기 기능이 필요한 경우 별도의 설정 디렉터리에 기존 설정을 복사하고, `NETWATCHER_WRITABLE_CONFIG_DIR`에 그 절대 경로를 지정합니다. 앱 계정에 해당 디렉터리의 파일 생성·교체 권한이 있어야 합니다.

```bash
mkdir -p config-write
cp -a config/. config-write/
export NETWATCHER_WRITABLE_CONFIG_DIR="$(pwd)/config-write"
docker compose -f docker-compose.yml -f docker-compose.config-write.yml up -d netwatcher
```

기존 PostgreSQL 스키마에 최신 마이그레이션을 적용한 뒤 사용하세요. 실패한 저장은 현재 설정을 바꾸지 않습니다. HTTP 응답만 보지 말고 적용 상태도 확인합니다.

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

사건·통계의 보존 기간과 패킷 파일의 저장 상한은 별개입니다. 검토 보존 중인 패킷은 일반 정리에서 제외되며 보존 상한은 64파일·32 MiB·24시간입니다.

## DB 장애 복구 파일

DB 저장이 확인되지 않은 사건을 재시작 후 복구하려면 다음 기능을 켭니다. 기본값은 꺼짐입니다.

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

기본 상한은 16 MiB·64파일·300초입니다. 디렉터리에는 서비스 계정만 접근하도록 하고 한 인스턴스만 사용합니다. 통계와 장치 정보는 이 디스크 복구 기능의 대상이 아닙니다. 복구 절차는 [운영 가이드](OPERATIONS-GUIDE.md#db-장애와-복구)를 참고하세요.

## 선택 기능

- **알림:** `.env`에 사용할 채널의 접속 정보만 설정하고 `alerts.channels`에서 활성화합니다. 설정 누락이나 잘못된 값은 채널 상태에서 확인합니다.
- **NetFlow/IPFIX:** 라우터가 flow 정보를 보낼 수 있다면 `netflow.enabled`, 수신 주소·포트를 설정합니다. 패킷 본문을 받는 기능은 아닙니다.
- **AI 분석:** 사용할 CLI를 준비하고 `ai_analyzer.enabled=true`로 설정합니다. `apply_mode`는 `propose`로 유지합니다. 분석에 전달될 자료와 외부 제공 범위를 먼저 검토하세요.
- **API 문서:** `web.enable_docs=true`로 켜면 `/docs`와 `/openapi.json`을 제공합니다. 운영망에서 공개할 필요가 없다면 기본값인 꺼짐을 유지합니다.

## 지원 범위

기본 `limited` 구성은 단일 센서·단일 워커, 고가용성 비활성, AI 제안 전용입니다. `full`을 지정해도 미구현 기능이 활성화되는 것은 아닙니다.

nftables 차단과 다중 사용자 로그인은 시작할 때 거부됩니다. 기본 `limited` 구성에서는 다중 워커와 고가용성도 사용할 수 없습니다. OS에 실제 적용하는 방화벽 경로는 iptables이며 기본값은 비활성입니다. 활성화 전에는 대상 트래픽 경로와 승인·만료·복구 절차를 별도로 검증해야 합니다.

전체 설정 항목은 [기본 설정 파일](../config/default.yaml)을 참고하세요.
