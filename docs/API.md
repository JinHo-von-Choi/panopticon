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

역할은 `viewer`(조회), `analyst`(분석·제안), `admin`(설정·승인) 순서로 권한을 포함합니다. 기본 로그인은 설정 계정 한 개를 사용합니다. `auth.multi_user=true`로 설정하면 개인별 계정과 역할을 관리할 수 있습니다. 계정의 역할·활성 상태·비밀번호를 변경하면 기존 토큰이 무효화되므로 다시 로그인해야 합니다.

차단·차단 목록·탐지 예외·규칙·장치·엔진 변경과 사건 해결 처리는 관리자 권한이 필요합니다. 변경 전 감사 기록을 저장할 수 없으면 503으로 거절합니다. 변경 후 결과 기록에 실패하면 `code=audit_outcome_unavailable`, `execution_status=unknown`, `request_id`를 반환합니다. 이때 같은 요청을 자동 재시도하지 말고 대상의 실제 상태와 감사 기록을 먼저 확인하세요.

관리자는 `GET /api/audit/changes/{request_id}`로 해당 변경의 의도·변경 전후 상태·결과를 확인할 수 있습니다. 일반 변경에는 응답의 `X-Request-ID`를, 분리 센서의 엔진·탐지 예외·차단 목록 변경에는 요청 본문의 `request_id`를 사용합니다. 센서 변경은 적용 기록이 확정되면 `outcome=applied`, 준비 기록만 있으면 `outcome=unknown`으로 응답합니다. 이는 해당 요청의 결과이며 이후 다른 변경까지 포함한 현재 상태는 대상 API로 조회하세요.

비밀값은 제외하고 설정의 자유 서술값은 해시로 기록합니다. `requires_reconciliation=true`이면 감사만으로 적용 여부를 확정할 수 없으므로 대상의 실제 상태를 확인해야 합니다. 감사 저장소 장애는 빈 이력 대신 503으로 응답합니다.

## 센서의 탐지 엔진

분리 Native 콘솔에서는 `GET /api/engines`로 엔진 목록을, `GET /api/engines/{name}`으로 현재 설정과 `base_version`을 조회합니다. 관리자는 `PATCH /api/engines/{name}/toggle`로 실행 상태를 지정합니다.

```json
{
  "request_id": "<새 UUID>",
  "base_version": "<조회 응답의 base_version>",
  "enabled": false
}
```

`enabled=true`는 활성화, `false`는 비활성화입니다. 별도 설정 항목이 없는 엔진도 변경할 수 있습니다. 설정값은 `PUT /api/engines/{name}/config`의 `config` 객체로 전달합니다. 요청에서 생략한 항목은 기존 설정을 유지하며, 설정 파일에도 없으면 엔진이 선언한 기본값을 사용합니다. 엔진이 선언한 항목과 공통 설정인 `enabled`, `tick_interval`을 사용하며, 실행 간격은 0보다 큰 숫자여야 합니다.

409이면 최신 설정을 다시 조회하고 변경 의도를 확인하세요. 503이면 적용 여부가 미확정일 수 있으므로 자동 재시도하지 말고 현재 설정과 변경 감사를 조회하세요.

## 센서의 시그니처 규칙

분리 Native 콘솔에서는 `GET /api/rules?limit=50&offset=0`으로 현재 적용된 규칙을 조회합니다. 페이지당 최대 50개를 반환합니다. `GET /api/rules/entry?rule_id=규칙ID`는 해당 규칙의 상세와 `base_version`을 반환합니다.

관리자는 `PUT /api/rules/entry`로 활성 상태를 지정합니다.

```json
{
  "request_id": "<새 UUID>",
  "base_version": "<조회 응답의 base_version>",
  "rule_id": "<변경할 규칙 ID>",
  "enabled": false
}
```

`POST /api/rules/reload`에는 `request_id`와 `base_version`을 전달합니다. 센서에 설정된 디렉터리의 규칙 파일을 다시 읽습니다. 파일 오류·중복 ID·지원하지 않는 포트 표현식이 있으면 변경을 거절하고 기존 규칙을 유지합니다.

활성 상태 변경은 현재 실행 중인 센서에 적용됩니다. 재로드하거나 센서를 다시 시작하면 파일의 설정을 따르므로 계속 유지할 변경은 규칙 파일에도 반영하세요. 이 API로 외부 Suricata의 규칙을 변경하지는 않습니다. 409이면 최신 규칙을 조회하고, 503이면 자동 재시도하지 말고 현재 규칙과 변경 감사를 확인하세요.

## 센서의 탐지 예외 목록

독립 Native 콘솔에서는 `GET /api/whitelist`로 목록과 `base_version`을 조회합니다. 관리자는 `PUT /api/whitelist/entry`로 항목을 추가하거나 제거합니다.

```json
{
  "request_id": "<새 UUID>",
  "base_version": "<조회 응답의 base_version>",
  "type": "ip",
  "value": "192.168.10.20",
  "present": true
}
```

`present=true`는 추가, `false`는 제거입니다. `type`은 `ip`, `ip_range`, `mac`, `domain`, `suffix` 중 하나이며 도메인 접미사는 `.example.com`처럼 점으로 시작합니다. 요청마다 새 UUID를 사용하세요. 같은 요청 ID의 재전송은 변경을 반복하지 않습니다.

409이면 목록을 다시 조회하고 변경 의도를 확인하세요. 503이면 적용 여부가 미확정일 수 있으므로 자동 재시도하지 말고 현재 목록을 먼저 조회하세요. 조회도 실패하면 센서 연결과 실행 상태를 확인한 뒤 다시 조회합니다. 센서 실행 중 설정 파일을 별도로 수정했다면 센서를 다시 시작해 파일과 탐지 상태를 일치시켜야 합니다.

## 센서의 위협 지표 목록

분리 Native 콘솔의 `/api/blocklist`는 탐지에 사용할 IP·CIDR·도메인을 관리합니다. 목록에 등록하는 것만으로 방화벽이 트래픽을 차단하지는 않습니다.

`GET /api/blocklist`로 목록을 조회합니다. `entry_type=ip|domain`, `source=custom|feed`, `search`로 필터링하고 `limit`(기본 50, 최대 100)과 `offset`으로 페이지를 선택합니다. 응답의 `total`은 필터에 맞는 전체 항목 수입니다. `GET /api/blocklist/stats`는 유형별 전체·사용자 항목 수를 반환합니다.

변경할 항목을 `GET /api/blocklist/entry?entry_type=ip&value=198.51.100.0%2F24`로 조회한 뒤, 관리자가 `PUT /api/blocklist/entry`에 다음 본문을 보냅니다.

```json
{
  "request_id": "<새 UUID>",
  "base_version": "<조회 응답의 base_version>",
  "type": "ip",
  "value": "198.51.100.0/24",
  "present": true,
  "notes": "조사로 확인한 악성 통신 대역"
}
```

`present=true`는 추가, `false`는 사용자 항목 삭제입니다. `type=domain`이면 `value`에 도메인을 넣습니다. 메모는 새 항목을 추가할 때 저장하며, 기존 항목을 다시 추가해도 덮어쓰지 않습니다. 항목 조회 응답의 `entry.notes`로 등록 근거를, `created_at`으로 실제 등록 시각을 확인합니다. 기존 메모가 2,048자를 넘으면 앞부분만 반환하고 `notes_truncated=true`로 표시합니다. 사용자 항목을 삭제해도 같은 지표가 외부 피드에 있으면 탐지를 유지합니다.

409이면 항목을 다시 조회해 변경 의도를 확인하세요. 503이면 적용 여부를 확정할 수 없으므로 자동 재시도하지 말고 항목과 감사 기록을 확인하세요. DB와 탐지 상태가 일치하지 않으면 조회도 실패합니다. 이때는 센서 상태를 확인하고, 센서를 다시 시작해 저장된 목록을 불러온 뒤 재조회하세요.

## 패킷 증거

Native 콘솔의 조회 권한으로 `GET /api/events/{id}/evidence/file`에서 PCAP을 내려받습니다. 파일당 최대 32MiB, 동시 2개를 지원합니다. 파일이 없으면 404, 저장 기능을 사용할 수 없으면 503입니다. 응답의 `Content-Length`와 `X-Content-SHA256`으로 크기와 파일 해시를 확인할 수 있습니다. 전송이 중단됐거나 크기·해시가 다르면 완성된 증거 파일로 사용하지 마세요.

분리 Native 콘솔에서는 먼저 `GET /api/events/{id}/evidence`로 현재 파일 상태와 `base_version`을 조회합니다. `state=available`이면 다운로드할 수 있습니다. `integrity=matched_record`는 저장 기록과 파일 해시가 일치한다는 뜻이고, `unrecorded`는 원기록에 비교할 해시가 없다는 뜻입니다.

관리자는 `POST /api/events/{id}/evidence/pin`에 다음 본문을 보내 보존 여부를 지정합니다.

```json
{
  "request_id": "<새 UUID>",
  "base_version": "<조회 응답의 base_version>",
  "enabled": true,
  "hours": 24,
  "reason": "사건 조사 자료 보존"
}
```

`enabled=false`는 검토 보존을 해제합니다. 보존 시간은 1~24시간, 사유는 3~500자이며 보존 상한은 64파일·32MiB입니다. 성공 응답의 `status=applied`, 동일한 `request_id`, `evidence.pin_state`를 확인하세요. 409이면 상태를 다시 조회하고 변경 의도를 검토합니다. 503이면 적용 여부가 불확실할 수 있으므로 자동 재시도하지 말고 상태와 `GET /api/audit/changes/{request_id}`를 확인하세요.

잘못된 요청은 422, 보존 상한이나 상태 충돌은 409입니다.

## 관련 경보를 묶은 사건

`GET /api/incidents`로 관련 경보를 묶은 사건 목록을, `GET /api/incidents/{id}`로 상세 내용을 조회합니다. 목록은 기본적으로 미해결 사건만 반환하며 `include_resolved=true`로 해결된 사건도 조회할 수 있습니다.

관리자는 `POST /api/incidents/{id}/resolve`로 해결 처리합니다. 성공 응답은 `{"status":"ok"}`입니다. 저장소 오류나 결과 감사 실패로 503을 받으면 요청을 자동으로 반복하지 말고 상세 조회로 `resolved` 상태를 확인하세요. 응답의 `X-Request-ID`가 있으면 변경 감사도 조회할 수 있습니다. 저장소 조회 오류는 빈 목록 대신 503으로 응답합니다.

## 상세 API 문서

`web.enable_docs=true`로 설정하고 재시작하면 `/docs`에서 요청·응답 형식을 확인하고 `/openapi.json`을 내려받을 수 있습니다. 활성화된 서비스에 따라 제공되는 경로가 달라질 수 있습니다. 이 설정은 API 설명을 노출하므로 접근 범위를 제한하세요.

## 자주 사용하는 경로

| 경로 | 용도 |
| --- | --- |
| `GET /api/auth/oidc/start` | 조직 계정 로그인 시작 |
| `GET /api/auth/oidc/callback` | 공급자의 로그인 응답 처리 |
| `POST /api/auth/oidc/session` | 같은 브라우저의 일회용 로그인 토큰 수령 |
| `GET /api/users` | 관리자 전용 계정 목록 |
| `GET /api/users/{id}` | 관리자 전용 계정 상세 |
| `POST /api/users` | 개인 계정 생성 |
| `PUT /api/users/{id}` | 역할·로그인 허용 상태 변경 |
| `POST /api/users/{id}/password` | 비밀번호 재설정 |
| `GET /api/users/{id}/identities` | 관리자 전용 외부 계정 연결 조회 |
| `POST /api/users/{id}/identities` | 외부 사용자 식별자를 개인 계정에 연결 |
| `DELETE /api/users/{id}/identities/{identity_id}` | 외부 계정 연결 해제 |
| `GET /api/events` | 사건 검색과 목록 |
| `GET /api/events/{id}` | 사건·장치 문맥·증거 상태 |
| `GET /api/events/{id}/case` | 담당자·처리 상태·인계 이력 |
| `PUT /api/events/{id}/case` | 담당자·처리 상태 변경과 인계 메모 추가 |
| `GET /api/reports/weekly` | 기간별 사건의 현재 처리 상태와 발생 횟수 보고서 |
| `GET /api/devices` | 장치 목록 |
| `GET /api/devices/{mac}` | 장치 상세 |
| `PUT /api/devices/{mac}/context` | 소유 관계·역할·기대 업무 확인 |
| `GET /api/health` | 구성요소 상태 |
| `GET /api/observation` | 관측과 누락 상태 |
| `GET /api/input/status` | EVE 수집 상태와 소스별 보존 사용량 |
| `GET /api/proposals` | 설정 제안과 승인 상태 |
| `POST /api/proposals` | 설정 후보 제출 |
| `GET /api/replay-capabilities` | 비교 가능한 엔진·파라미터·상한 |
| `POST /api/replay-runs` | 변경 전후 비교 시작 |
| `GET /api/replay-runs/{id}/diff` | 비교 결과 조회 |
| `POST /api/proposals/{id}/validation` | 정상·공격 실행을 제안에 연결 |
| `POST /api/proposals/{id}/approve` | 관리자 승인·적용 |
| `POST /api/proposals/{id}/reject` | 관리자 거절 |

각 경로의 필수값·필터·상한은 OpenAPI 문서를 확인하세요. 승인 응답은 HTTP 상태뿐 아니라 `status`, `applied`, `error`도 확인해야 합니다.

EVE 모드에서 Viewer 이상은 `/api/input/status`로 전체 `status`, 소스별 `sources`, 보존 사용량 `storage`를 조회합니다. DB 사용량 조회 실패는 503입니다. `/api/observation`의 `sources`에도 같은 수집 상태가 포함됩니다. 소스의 `pending_bytes`는 현재 읽는 파일에서 아직 DB에 저장하지 않은 바이트 수이며, 조회할 수 없으면 `null`입니다. `pending_scope`는 `active_file`이고 다른 회전 파일의 대기량과 IDS 패킷 손실은 포함하지 않습니다. `backlog:true`는 대기량이 배치 바이트 상한의 두 배를 초과했음을 뜻하며 수집 상태는 `degraded`입니다. 대기량 미확인이나 누락·거절 기록도 `degraded`, 수집 오류나 30초 이상 미갱신은 `unhealthy`로 표시합니다. `/ready`는 DB와 수집 상태가 모두 `healthy`일 때만 200을 반환하고, 그 외에는 503을 반환합니다.

계정 API는 관리 계정 모드에서 관리자만 사용할 수 있습니다. 생성 요청에는 `username`, `password`, `role`을 넣습니다. 역할·활성 상태 변경에는 현재 `version`을 `expected_version`으로, 새 값을 `role`·`enabled`로 보냅니다. 비밀번호 재설정에는 `expected_version`과 `password`를 넣습니다. 버전 충돌과 마지막 관리자 보호는 409, 잘못된 입력은 422로 응답합니다. 계정 생성 한도는 1,000개이며 응답과 감사 기록에 비밀번호·해시를 반환하지 않습니다.

외부 계정 연결에는 OIDC 공급자의 발급자 주소 `issuer`, 사용자 식별자 `subject`, 현재 계정의 `expected_version`을 보냅니다. 발급자 주소는 HTTPS여야 하며 두 식별자는 대소문자를 포함해 정확히 비교합니다. 공급자마다 개인 계정 하나에 식별자 하나를 연결할 수 있고, 같은 식별자를 여러 계정에 연결할 수 없습니다. 연결 해제 요청 본문에는 `expected_version`을 넣습니다. 연결하거나 해제하면 계정 버전이 올라가 기존 로그인이 해제됩니다. 조회 응답에는 `user`와 `identities`가 포함됩니다. 권한은 Panopticon에 등록한 역할을 따르며, 감사 기록에는 외부 식별자의 해시를 남깁니다.

OIDC 설정과 계정 연결은 [조직 계정 로그인 설정](CONFIGURATION.md#조직-계정으로-로그인)을 따릅니다. 콘솔 브라우저는 콜백 후 `/api/auth/oidc/session`을 한 번 호출해 토큰을 받습니다. 이 요청에는 콘솔과 같은 출처의 `Origin` 헤더와 로그인 중 발급한 보안 쿠키가 필요합니다. 전달 유효 시간은 30초이며 수령한 토큰은 기존 `Authorization: Bearer` 방식으로 사용합니다. 응답이 끊겼으면 새 로그인으로 다시 시작합니다. 토큰은 리다이렉트 주소에 포함되지 않습니다.

사건을 개인에게 배정하려면 `PUT /api/events/{id}/case`에 `owner_id`(계정 ID), `status`, `note`, `expected_version`을 보냅니다. `owner`를 함께 보내면 선택한 계정의 사용자 이름과 일치해야 합니다. 비활성 계정에는 새 사건을 배정할 수 없습니다. 기존 배정은 유지되며 다른 담당자로 변경하거나 인계 메모를 기록할 수 있습니다.

`owner_id=null`과 `owner`를 보내면 계정 연결 없이 표시 이름만 기록합니다. `owner`도 빈 문자열이면 미배정입니다. 기존 담당자 이름을 그대로 보내고 `owner_id`를 생략하면 기존 계정 연결을 유지합니다. 사건 응답에는 담당자 `owner_id`, 작성자 `actor_id`, 담당 계정의 `owner_enabled`가 포함됩니다. `GET /api/events`와 `/api/events/export`의 `case_owner_id`로 해당 계정에 배정된 사건만 조회할 수 있습니다. 주간 보고서와 CSV에도 담당 계정 ID가 포함됩니다.

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

## 사건별 업무 판정

`GET /api/events/{event_id}/business-review`는 조회 권한으로 현재 판정과 재검토 사유를 반환합니다. `PUT`은 관리자 권한과 필수 감사 기록이 필요합니다.

```json
{
  "decision": "expected_backup",
  "note": "백업 일정과 담당자를 확인했습니다.",
  "expected_version": 0,
  "valid_hours": 24,
  "max_bytes": 10485760
}
```

- `decision`: `investigate`(조사 필요), `insufficient_evidence`(근거 부족), `expected_backup`(확인한 백업), `approved_maintenance`(승인된 점검).
- `expected_version`: 최초 기록은 0, 수정은 GET이 반환한 현재 버전. 충돌하면 409를 반환합니다.
- `note`: 3~512자의 판정 근거.
- `valid_hours`: 정상 판정의 유효 시간, 1~168시간. 장치 역할 확인의 만료 시각을 넘지 않습니다.
- `max_bytes`: 정상 판정에 필요한 EVE 흐름의 전송량 상한. 최대 1TiB이며 초과·근거 누락은 정상 판정을 거절합니다.

정상 판정은 단일 EVE 사건에만 적용합니다. 소유 관계와 센서·입력·흐름 ID·주소·프로토콜·포트를 검사합니다. 흐름의 `start`~`end` 구간에 경보 시각이 포함되면 파일 세대가 달라도 연결합니다. `end`는 마지막 패킷 시각이며 통신 종료를 보장하지 않습니다. 두 시각이 모두 없는 기록은 같은 파일 세대에서 경보 시각 전후 5분으로 연결을 제한합니다. 한 시각만 있는 기록은 판정 근거로 사용하지 않습니다. 같은 통신의 누적량 증가가 승인 한도 안이면 판정을 유지합니다. 후보가 64개를 넘거나 시작점·MAC·동일 시각의 카운터가 충돌하면 `flow_evidence_ambiguous`, 방향별 카운터가 감소하면 `flow_counter_reset`으로 재검토합니다. 원래 경보와 심각도는 유지합니다. 응답 `state`는 `unreviewed`, `normal_confirmed`, `needs_review`, `investigate`, `insufficient_evidence` 중 하나입니다. `reason`은 재검토나 거절 사유이며, 기존 판정은 `review`에 포함됩니다.


## 업무 판정 변경 이력

`GET /api/events/{event_id}/business-review/history`는 viewer 이상 권한으로 조회합니다. 최신순 판정 기록 `history`와 다음 페이지 기준 `next_before_version`을 반환합니다. 한 페이지는 최대 50건이며 다음 페이지는 `?before_version={next_before_version}`으로 조회합니다. 다음 기준이 null이면 마지막 페이지입니다.

각 기록은 당시 `version`, `decision`, `note`, `actor`, `scope`, `reviewed_at`, `expires_at`을 보존합니다. 새로 저장한 정상 판정의 `scope.asset_context`에는 당시 확인한 장치 역할·확인자·확인 시각·만료 시각을 저장합니다. 과거 기록은 현재 유효성을 다시 계산한 판정이 아닙니다. 현재 상태는 기존 업무 판정 조회 API에서 확인합니다.

최신 판정과 이력은 같은 트랜잭션으로 저장합니다. 기존 이력을 수정·삭제하는 API는 제공하지 않습니다. 사건별 기록이 1,000건이면 추가 변경은 `409 history_capacity`로 거절합니다. 보존 정리로 원래 사건·판정을 삭제하면 이력도 삭제합니다. 이전 버전에서 업그레이드하면 남아 있는 최신 판정만 보존하며 이미 덮어쓴 과거 근거를 복원하지 않습니다.

## 사건 담당자와 인계

`GET /api/events/{event_id}/case`는 viewer 이상, `PUT /api/events/{event_id}/case`는 admin 권한이 필요합니다. 변경에는 필수 감사와 버전 비교를 적용합니다.

```json
{
  "owner": "야간 담당자",
  "status": "investigating",
  "note": "백업 담당자에게 통신 상대 확인을 인계합니다.",
  "expected_version": 0
}
```

`owner`는 최대 128자의 이름·팀명이며 빈 문자열로 미지정 상태를 기록할 수 있습니다. 로그인 계정 검증이나 권한 부여에 사용하지 않습니다. `status`는 `open`, `investigating`, `closed`입니다. `note`는 3~1,024자입니다. `expected_version`은 최초 기록 시 0, 이후에는 GET이 반환한 현재 `case.version`을 사용합니다. 버전 충돌은 `409 version_changed`입니다.

응답은 현재 담당자·처리 상태인 `case`, 최신순 기록 `history`, 다음 페이지 기준 `next_before_version`을 포함합니다. 한 페이지는 최대 50건이며 다음 페이지는 `?before_version={next_before_version}`으로 조회합니다. 다음 값이 null이면 마지막 페이지입니다. 인계 기록의 수정·삭제 API는 제공하지 않습니다. 사건별 1,000건을 넘는 변경은 `409 history_capacity`로 거절합니다.

처리 상태는 원래 경보·심각도·업무 판정을 변경하지 않습니다. 보존 정리로 사건을 삭제하면 담당자·인계 이력도 삭제합니다.


## 사건 목록 필터와 기간 보고서

`GET /api/events`와 `GET /api/events/export`에 `case_owner`, `case_status`를 지정할 수 있습니다. `case_owner`는 정확히 일치하는 담당자 이름·팀명이며 빈 문자열은 미지정입니다. 생략하면 전체 담당자를 조회합니다. `case_status`는 `open`, `investigating`, `closed` 중 하나입니다. 인계 기록이 없는 사건은 미지정·`open`으로 조회합니다. 목록에는 `case_owner`, `case_status`가 포함됩니다. 내보내기도 `q` 검색과 이 필터를 적용합니다.

`GET /api/reports/weekly`는 viewer 이상 권한으로 조회합니다. `start`, `end`는 시간대가 있는 ISO 8601 시각이며 시작은 포함하고 끝은 제외합니다. 생략하면 현재 시각까지 최근 7일입니다. 기간은 최대 31일, 보존 사건은 최대 10,000건입니다. 초과 시 `413 report_capacity`를 반환하며 일부 자료만 출력하지 않습니다.

JSON 응답은 `period`, `snapshot_at`, `summary`, `events`를 포함합니다. 사건 발생 시각으로 범위를 정하고 조회 시점의 담당자·상태·마지막 인계 메모를 보여줍니다. 기간 중의 처리 활동 이력이나 이미 삭제된 사건을 집계한 결과가 아닙니다.

- `summary.stored_events`: 기간에 속한 보존 사건 수.
- `summary.known_occurrences`: 확인 가능한 반복 발생 횟수의 합. 반복 집계가 없는 사건은 1로 계산합니다.
- `summary.unknown_occurrence_events`: 반복 집계가 있지만 유효한 발생 횟수를 확인할 수 없는 사건 수.
- `summary.occurrences_complete`: 모든 사건의 발생 횟수를 확인할 수 있으면 true.
- `summary.by_status`, `summary.by_severity`: 저장 사건의 현재 처리 상태별·원래 심각도별 수.

`format=csv`는 조회 기간·시각과 사건별 상태·인계 메모를 UTF-8 CSV로 반환합니다. 발생 횟수를 모르면 `occurrence_count`가 빈칸입니다. 빈 결과도 열 이름을 출력합니다. 스프레드시트에서 수식으로 해석될 수 있는 문자열 앞에는 작은따옴표를 붙이며 JSON 응답의 원문은 바꾸지 않습니다.


## 작업 일정

viewer 이상은 `GET /api/work-schedules`와 `GET /api/events/{event_id}/work-schedule`로 등록·일치 일정을 조회합니다. `limit` 기본 50·최대 100, `offset` 기본 0입니다. 사건 조회는 현재 연결 `current`, 일치 목록 `matches`, 일치 건수 `total_matches`를 반환합니다. 일치 판정에는 EVE 사건의 시각·장치·상대·프로토콜·포트를 사용합니다.

admin은 `POST /api/work-schedules`로 일정을 등록합니다.

```json
{
  "title": "야간 백업",
  "kind": "backup",
  "owner": "백업 담당자",
  "ticket": "CHG-001",
  "note": "백업 상대와 승인 시간 범위를 확인했습니다.",
  "source_ip": "192.0.2.10",
  "source_mac": "02:00:00:00:00:10",
  "dest_ip": "198.51.100.20",
  "protocol": "TCP",
  "dest_port": 443,
  "starts_at": "2026-10-08T00:00:00Z",
  "ends_at": "2026-10-08T02:00:00Z",
  "max_flow_bytes": 10485760
}
```

`kind`는 `backup`, `vulnerability_scan`, `deployment`, `maintenance`입니다. `source_mac`과 `dest_port`는 null로 생략할 수 있으며, 각각 IP 기준 매칭·해당 상대의 전체 포트를 뜻합니다. 기간은 양수·최대 31일이며 시작을 포함하고 종료를 제외합니다. `max_flow_bytes`는 흐름 하나의 전송량 상한으로 최대 1TiB입니다. 작업 전체의 누적량 상한이 아닙니다.

응답은 `created_ids`, `existing_count`, `duplicate_rows`입니다. 정규화한 내용이 같은 일정은 기존 기록으로 처리합니다. 취소한 동일 일정도 새 승인으로 되살리지 않습니다.

`POST /api/work-schedules/import`의 본문은 `{"csv":"..."}`입니다. 열은 위 JSON의 모든 필드명을 사용합니다. `source_mac`, `dest_port`는 빈칸으로 입력할 수 있습니다. UTF-8 기준 최대 128KiB·100행입니다. 열 이름·행 입력 오류는 422이며 잘못된 행은 행 번호만 반환합니다. 입력과 DB 저장 모두 전체 배치를 검증하며 일부만 등록하지 않습니다.

`PUT /api/events/{event_id}/work-schedule`의 본문은 `{"schedule_id":"UUID","expected_version":0}`입니다. 최초 연결은 0, 변경은 `current.version`을 사용합니다. 범위 불일치·취소 일정은 `409 schedule_scope_mismatch`, 동시 변경은 `409 version_changed`입니다.

`POST /api/work-schedules/{id}/revoke`는 `expected_version`과 3~512자의 `note`를 받습니다. 취소 기록을 보존하며 원래 내용을 수정·삭제하는 API는 제공하지 않습니다. 등록·가져오기·연결·취소에는 관리자 권한과 필수 감사를 적용합니다.

연결이 있는 사건의 정상 판정은 `scope.work_schedule`에 당시 일정·등록자·등록 시각·연결 버전을 보존합니다. 판정 한도가 일정의 `max_flow_bytes`를 넘으면 `409 work_volume_limit`입니다. 이후 취소·연결 변경·범위 변경은 각각 `work_cancelled`, `work_link_changed`, `work_scope_invalid`로 재검토합니다. 일정 등록은 원래 경보·심각도·탐지 설정을 바꾸지 않습니다.

보관 한도는 2,000건이며 초과 시 `409 schedule_capacity`입니다. 등록 시 종료 후 90일이 지난 미연결 일정을 정리합니다. 연결 일정은 사건 보존 정리로 연결이 해제된 뒤 정리 대상이 됩니다. 조회 중인 과거 판정의 일정 스냅샷은 판정 이력에 남습니다.

### 반복 경보

`GET /api/events/{event_id}/group` — Viewer 이상. EVE 경보와 같은 UTC 1시간 구간의 반복 경보를 조회합니다. `offset`은 기본 0, `limit`은 기본 50·최대 100입니다. 정렬은 발생 시각 내림차순, 같은 시각에서는 경보 ID 내림차순입니다.

응답에는 `window`(시작 포함·종료 제외), `snapshot_at`, `scope`, `total`, `without_review`(업무 판정 기록 없음), `not_closed`(미종결), `first_seen`, `last_seen`, `events`가 포함됩니다. `events`의 `recorded_decision`은 저장된 마지막 판정이며 현재 유효한 정상 판정임을 보장하지 않습니다. 현재 판정은 해당 경보의 `business-review`에서 확인합니다.

묶음 기준은 센서·입력 ID, 출발지·목적지 IP와 MAC 정보, 프로토콜·목적지 포트, 규칙 ID·gid·개정·심각도·동작입니다. 흐름 ID와 출발 포트는 제외합니다. IP가 빠진 경보는 단독으로 반환합니다. 일반 경보는 `available:false`, 없는 경보는 404, 저장소 오류 또는 조회 시간 초과는 503입니다. 원본과 경보별 판정·처리 상태는 수정하지 않습니다.

`GET /api/events/groups` — Viewer 이상. `start`·`end`는 시간대가 있는 시각이며 시작 포함·종료 제외, 기본 최근 24시간·최대 7일입니다. `offset`은 기본 0, `limit`은 기본 50·최대 100입니다. 조회 시점의 보존 EVE 경보만 집계합니다. 기간 내 경보가 50,000건을 넘으면 413 `group_period_capacity`, 조회 실패·5초 초과는 503입니다.

응답의 `stored_alerts`는 기간 내 원본 경보 수, `total`은 묶음 수입니다. `groups`는 `scope`, `window_start`, `occurrences`, `without_review`, `not_closed`, `first_seen`, `last_seen`, `representative_id`, `title`, `severity`를 포함합니다. 대표는 가장 최근 경보이고, 같은 시각이면 가장 큰 ID입니다. 정렬은 심각도(CRITICAL→WARNING→INFO), 미판정 기록 수 내림차순, 미종결 수 내림차순, 최근 발생 시각과 대표 ID 내림차순입니다. 목록의 집계는 요청 기간으로 제한하며 개별 경보의 `/group` 상세는 해당 UTC 1시간 전체를 반환합니다. 원본 경보와 저장된 판정은 수정하지 않습니다.

### 처리 우선순위

`GET /api/investigation/priorities` — Viewer 이상. `category`는 `unclosed`(기본), `unassigned`, `unreviewed`, `expired`, `recheck` 중 하나입니다. `offset` 기본 0, `limit` 기본 50·최대 100. 발생 시각 범위 없이 보존 중인 전체 사건을 한 DB 스냅샷으로 집계합니다.

`counts`의 `stored_events`는 전체 보존 사건 수입니다. `unclosed`는 미종결, `unassigned`는 미배정·미종결, `unreviewed`는 업무 판정 기록 없음·미종결, `expired`는 정상 판정의 기한 만료 수입니다. `expired`는 `expected_backup` 또는 `approved_maintenance` 판정의 `expires_at`이 조회 시점 이하인 사건이며 종결 여부와 무관합니다. 분류는 중복될 수 있습니다. 기한 만료 이외의 재검토 사유는 `recheck` 분류로 조회합니다.

응답의 `category`, `total`, `offset`, `limit`, `events`는 선택한 분류의 목록이고 심각도·최근 발생 시각·ID 내림차순으로 정렬합니다. `snapshot_at`과 `scope:all_retained_events`를 함께 반환합니다. 탐지 설정 제안 기능이 있으면 `proposals_available:true`와 `pending_proposals`를 반환하며, 없으면 false와 null입니다. 조회 실패·5초 초과는 503이고, 원본 경보·판정·처리 상태는 변경하지 않습니다.

`category=recheck`는 보존 중인 `expected_backup`·`approved_maintenance` 판정을 단일 사건의 업무 판정과 같은 로직으로 평가합니다. 평가와 목록은 하나의 DB 스냅샷·같은 시각 기준입니다. 현재 상태가 `needs_review`인 사건을 반환하며 `events`에 `review_state`, `review_reason`을 추가합니다. 사건 종결 여부와 무관하고 기존 판정·이력을 수정하지 않습니다.

`recheck_evaluated:true`일 때 `counts.recheck`와 `total`은 전체 평가 결과입니다. 다른 분류는 `recheck_evaluated:false`, `counts.recheck:null`이며 재검토 수를 0으로 추정하면 안 됩니다. 정상 판정 후보가 1,000건을 넘으면 413 `review_evaluation_capacity`, 전체 조회·평가가 5초를 넘으면 503입니다. 일부 후보만 평가해 전체 건수처럼 반환하지 않습니다.

### 같은 조건의 이전 경보

`GET /api/events/{event_id}/similar` — Viewer 이상. `days` 기본 30·최대 90, `offset` 기본 0, `limit` 기본 50·최대 100입니다. 기준 사건이 속한 UTC 1시간 묶음의 시작 직전부터 `days`일 앞까지, 시작 포함·종료 제외로 조회합니다. 센서·입력 ID, 규칙 ID·gid·개정·심각도·동작, 출발지·목적지 IP/MAC 정보, 프로토콜·목적지 포트가 같은 보존 EVE 경보만 반환합니다. 출발 포트와 흐름 ID는 제외합니다.

응답은 `view:previous_same_scope`, `window`, `scope`, `snapshot_at`, `total`, `without_review`, `not_closed`, `events`를 포함합니다. 사건별로 최신 담당자·처리 상태와 `recorded_decision`, `review_note`, `reviewer`, `reviewed_at`, `expires_at`, `recorded_asset_context`, `handover_note`를 반환합니다. 기록된 판정의 현재 유효 여부는 해당 사건의 `business-review`에서 확인합니다. 이전 판정을 현재 경보에 적용하거나 원본·판정·인계 기록을 수정하지 않습니다.

주소 정보가 부족하면 `available:false, reason:addresses_required`, EVE 경보가 아니면 `available:false, reason:eve_alert_required`입니다. 없는 사건은 404, 조회 실패·5초 초과는 503입니다. MAC이 없는 같은 IP의 기록을 동일 장치의 경보로 보장하지 않습니다.

### 보존 EVE 기록의 첫 관측

`GET /api/investigation/observations` — Viewer 이상. `kind`는 `addresses`(기본) 또는 `peers`, `hours` 기본 24·최대 168, `offset` 기본 0, `limit` 기본 50·최대 100입니다. 보존 중인 전체 alert·flow·dns·tls 기록에서 항목별 최초·최종 관측 시각을 계산한 뒤, 최초 관측이 조회 시각부터 `hours`시간 전 사이인 항목을 반환합니다. 범위 양끝을 포함합니다.

주소 항목의 `scope`는 센서·입력·IP·단일 MAC 정보이고, 통신 항목은 센서·입력·출발지/목적지 IP와 단일 MAC 정보·프로토콜·목적지 포트입니다. 다중 MAC 배열에서 단일 장치 신원을 추정하지 않습니다. 출발 포트와 흐름 ID는 통신 항목 구분에서 제외합니다. `identity_confirmed:false`는 이 집계에서 장치 소유 관계를 확정하지 않는다는 뜻입니다.

`scope:all_retained_eve_records`, `snapshot_at`, `period`, `baseline`, `total`, `observations`를 반환합니다. `baseline`은 집계 대상 보존 기록 수, 가장 오래된/최근 관측 시각, 미래 시각 기록 수를 담습니다. 항목은 `first_seen`, `last_seen`, `observations`(주소는 출발·목적지 출현 수, 통신은 기록 수), `related_event_id`를 담습니다. 연결할 보존 경보가 없으면 related_event_id는 null입니다. 처음 관측된 시각 내림차순, 같은 시각이면 scope의 고정 순서로 페이지를 조회합니다.

보존 로그 전체에서 확인된 최초 시각이며 영구적인 최초 발견이나 망 전체의 관측을 보장하지 않습니다. 미래 시각만 가진 항목은 최근 첫 관측에서 제외합니다. 집계 대상 250,000건 초과는 413 `observation_history_capacity`, 조회 실패·5초 초과는 503입니다. 원본·경보·장치·판정을 수정하지 않습니다.
