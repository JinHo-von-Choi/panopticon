# API 사용

Panopticon API로 사건 조회, 장치 확인, 설정 제안과 검증을 연동할 수 있습니다. 주소와 인증 정보는 운영 환경에 맞춰 사용하세요.

## 로그인

```http
POST /api/auth/login
Content-Type: application/json

{"username": "<로그인 계정>", "password": "<로그인 비밀번호>"}
```

성공 응답의 `token`을 이후 요청에 넣습니다.

```http
GET /api/events?limit=20
Authorization: Bearer <token>
```

HTTP 401이면 로그인과 토큰 만료를, 403이면 역할을 확인합니다. 429이면 요청 속도를 낮추고 `Retry-After`가 있으면 해당 시간 후 재시도합니다.

역할은 `viewer`(조회), `analyst`(분석·제안), `admin`(설정·승인) 순서로 권한을 포함합니다. 기본 로그인은 관리자 계정 한 개를 사용하며, 다중 사용자 계정 발급 기능은 제공하지 않습니다.

## 상세 API 문서

`web.enable_docs=true`로 설정하고 재시작하면 `/docs`에서 요청·응답 형식을 확인하고 `/openapi.json`을 내려받을 수 있습니다. 활성화된 서비스에 따라 제공되는 경로가 달라질 수 있습니다. 이 설정은 API 설명을 노출하므로 접근 범위를 제한하세요.

## 자주 사용하는 경로

| 경로 | 용도 |
| --- | --- |
| `GET /api/events` | 사건 검색과 목록 |
| `GET /api/events/{id}` | 사건·장치 문맥·증거 상태 |
| `GET /api/devices` | 장치 목록 |
| `GET /api/devices/{mac}` | 장치 상세 |
| `PUT /api/devices/{mac}/context` | 소유 관계·역할·기대 업무 확인 |
| `GET /api/health` | 구성요소 상태 |
| `GET /api/observation` | 관측과 누락 상태 |
| `GET /api/proposals` | 설정 제안과 승인 상태 |
| `POST /api/proposals` | 설정 후보 제출 |
| `GET /api/replay-capabilities` | 비교 가능한 엔진·파라미터·상한 |
| `POST /api/replay-runs` | 변경 전후 비교 시작 |
| `GET /api/replay-runs/{id}/diff` | 비교 결과 조회 |
| `POST /api/proposals/{id}/validation` | 정상·공격 실행을 제안에 연결 |
| `POST /api/proposals/{id}/approve` | 관리자 승인·적용 |
| `POST /api/proposals/{id}/reject` | 관리자 거절 |

각 경로의 필수값·필터·상한은 OpenAPI 문서를 확인하세요. 승인 응답은 HTTP 상태뿐 아니라 `status`, `applied`, `error`도 확인해야 합니다.

## 비교 입력

대시보드 업로드 파일은 특징값 객체 배열입니다. PCAP을 업로드하는 기능은 아닙니다.

```json
[
  {
    "src_ip": "192.0.2.10",
    "dst_ip": "192.0.2.20",
    "src_mac": "02:00:00:00:00:10",
    "dst_mac": "02:00:00:00:00:20",
    "dst_port": 443,
    "bytes": 1024,
    "ts": 1791410400,
    "ip_proto": "tcp"
  }
]
```

주소는 문서용 예시이며 실제 기록으로 바꿔야 합니다. `ts`는 초 단위 Unix 시각, `bytes`는 관측한 전송량입니다. 이 한 행은 형식 예시이며 스캔 검증에 충분한 샘플은 아닙니다.

정상과 공격은 서로 다른 입력을 준비하고 담당자가 분류를 확인합니다. API에서는 `records`, `engines`, 변경 전후 파라미터와 버전, `input_label`, `label_confirmed`, `proposal_id`를 제출합니다. 현재 빌드 버전은 `GET /api/replay-capabilities`에서 확인할 수 있습니다.

```http
POST /api/proposals/{proposal_id}/validation
Authorization: Bearer <token>
Content-Type: application/json

{"normal_run_id": 101, "attack_run_id": 102}
```

실행 ID는 실제 정상·공격 결과의 ID로 바꿉니다. 현재 제안 승인 연결은 `port_scan.threshold` 변경을 지원합니다. 공격 관측의 유실·변경, 기준 설정 차이, 불완전 입력이나 지원하지 않는 변경은 거부됩니다.

## 비교와 파일 상한

대시보드 파일은 각각 768 KiB, API 요청 본문은 1 MiB, 비교 입력은 50,000행 상한입니다. 비교는 동시 한 개를 실행하며 실행·대기를 합쳐 기본 2개·32 MiB입니다. 대기는 300초, 실행은 600초를 넘으면 중단될 수 있습니다.

## 패킷 증거

`GET /api/events/{id}/evidence/file`은 현재 존재하는 파일을 내려받습니다. 파일이 없으면 404, 저장 기능을 사용할 수 없으면 503입니다.

관리자는 `POST /api/events/{id}/evidence/pin`에 `enabled`, `hours`(1~24), `reason`을 보내 보존 또는 해제를 요청합니다. 잘못된 요청은 422, 보존 상한이나 상태 충돌은 409입니다.
