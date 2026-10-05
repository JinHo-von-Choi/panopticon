# 실행계획 검토 및 Stage 1(PR 01~03) 구현 기록

- 원문: `https://cloud.nerdvana.kr/index.php/s/Ty5x3G3jpBKTDEY/download` (PDF 19쪽, 16-PR 로드맵)
- 기준 커밋: `d7c8dff`
- 작성일: 2026-10-05

---

## 1. 계획서 구조 요약

| 구간 | 내용 | 규모 |
|-|-|-|
| 1장 | 문제 정의 · 운영·검증에 집중 | - |
| 2장 | 시장·경쟁·일반 제품 문서 | - |
| 3장 | 지원 모드(제한/일반/확장) 결정 | - |
| 4장 | G0~G10 게이트 매트릭스 (G0 G1 G2 G3 G4 G6 G7 G8 G9 G10) | - |
| 5장 | 작동 경계 (한, 이 경계를 넘지 않는다) | - |
| 6장 | 16개 PR 표면 (PR 01~16) | - |
| 7장 | 증거 조각 규격 | - |
| 8장 | 리플로이 포인트 | - |
| 9장 | 범위 밖 목록 | - |
| 10장 | 산출물 | - |
| 11~15장 | 전사 배치 / 반환 검증 / 상시 실행 루프 / Day 1~2 Week 1~4 / 추진자 역할 | - |
| 16~19장 | 수락 기준 (gate → 노예 → 운영) | - |

계획서가 스스로 정한 첫 실행 단위는 **"지원 모드와 출시 게이트 문서 확정 → 기존 결함을
안전한 회귀 fixture로 이동 → PR 01~11 수직 슬라이스"** 다. 이에 따라 이번 턴에는
Stage 1(PR 01~03)을 구현하고, 나머지는 다음 실행 단위로 남긴다.

---

## 2. 프로젝트 현황 (기준 커밋 `d7c8dff`)

실제로 확인한 규모:

- 엔진 22종(`netwatcher/detection/engines/`) + NetFlow 엔진 2종 + ML 엔진 1종
- 저장 계층 7 테이블, 마이그레이션 head `009_users_and_audit`
- 대시보드: 빌드 단계 없는 바닐라 ES 모듈 10개 (`static/js/modules/`)
- 웹 라우터 15개, 대시보드 JS 총 ~1,600줄

**이미 성숙한 부분** (재작업 불필요)

- `config_schema` 기반 엔진 파라미터 선언 → 대시보드 설정 UI가 이미 스키마를 읽는다
- 주기적 체크포인트·상태 저장, 프로메테우스 지표, 구조화 로깅
- `pkexec` 게이트를 통과한 iptables 적용 경로 (`response/blocker.py:240-247`)
- 24개 이상의 테스트 디렉터리, 엔진 테스트는 DB 없이 실행된다

**계획서 전제가 코드와 어긋나던 지점** (이게 Stage 1의 실제 대상이었다)

| 계획서 전제 | 실제 코드 | 처리 |
|-|-|-|
| "인증·설정 검사가 app 조립 경로를 통과해야 한다" | `NetWatcher.run()` 에 검증 단계가 전혀 없음 | `netwatcher/support.py` 신설, 기동 직전 강제 |
| "허용되지 않은 키·bool·NaN·범위 초과는 거부" | `validate_config()` 가 **경고 문자열만 반환**하고 적용을 막지 않음 | 거부 기반 `netwatcher/detection/validation.py` 신설 |
| "Host·DNS·nickname 는 실제 DOM 값으로만 출력" | `esc()` 가 `textContent→innerHTML` 왕복이라 **따옴표 미이스케이프** | 6문자 이스케이프 + 인라인 핸들러 5곳 제거 |
| "AI 는 승인 없이 설정을 바꾸지 않는다" | AI 가 `yaml_editor.update_engine_config()` + `reload_engine()` 을 **직접 호출** | 제안 전용으로 축소 |
| "읽기/제안/승인 3역할" | `web/rbac.py` 는 있으나 **어떤 라우터도 사용하지 않음**, `app.state.auth_manager` 미설정이라 조용히 anonymous-admin 통과 | 엔진 설정 쓰기 경로에 ADMIN 요구 연결 |

---

## 3. Stage 1 구현 내용

### PR 01 — 지원 프로필 + CI 계약 (`netwatcher/support.py`)

프로필(`limited` / `full`)과 구성 조합 검증을 분리했다. 핵심 원칙은 계획서의
"비활성화는 결함 수정 완료가 아니다"를 코드에 박는 것이다.

- `enforce_support()` 을 `NetWatcher.run()` 에서 **DB 연결 이전**에 호출 → 위반 시 어떤
  컴포넌트도 시작되지 않고 종료
- 거부 항목: nftables/mock 백엔드, 영구차단(TTL 0), `INPUT` 체인, AI `apply_mode`,
  인증 없는 외부 바인드 + CORS 와일드카드, JWT secret 누락, `multi_user`, 잘못된
  ssl_mode/포트, `limited` 프로필의 멀티워커·HA
- `GET /api/support-profile` 로 프로필·검증된 enforcement 백엔드·위반 목록을 노출
  (대시보드가 "차단이 실제로 적용된다"고 오인하지 않도록)

코드:

- `netwatcher/support.py` (신규)
- `netwatcher/app.py` (기동 시 강제 검증)
- `netwatcher/web/server.py` (`/api/support-profile`)
- `config/default.yaml` (`support.profile: limited`, 백엔드 주석 정정)

### PR 02 — 안전한 UI 출력

- `esc()` 를 6문자(`& < > " ' \``) 이스케이프로 교체하고 `escAttr()` / `textEl()` 추가
- 인라인 `onclick="${...}"` 5곳을 `data-*` 속성 + `addEventListener` 로 교체
  (`devices.js` 2, `blocklist.js` 1, `whitelist.js` 1, `events.js` 1)
- `risk-${level}` 클래스에 이스케이프 적용, `row()` 조립 헬퍼가 값을 항상 이스케이프하도록
  HTML 조각은 `htmlRow()` 으로 분리
- **게이트 테스트**(`tests/test_web/test_ui_output_safety.py`)가 이후 회귀를 막는다.
  실제로 이 게이트가 남은 싱크 1개(`events.js:97`)를 찾아냈다.

### PR 03 — 엄격 검증 · 역할 분리 · AI 격리

- `netwatcher/detection/validation.py` (신규): 선언되지 않은 키, bool↔int 강제 변환,
  NaN/Inf, min/max, 시간 파라미터 0/음수, 누적 제한을 모두 **거부**한다
- 엔진 설정 API 는 검증을 통과해야만 `reload_engine()` → YAML 기록 순으로 진행한다.
  병합 결과까지 재검증해, 기존 YAML 이 이미 어긋나 있으면 새 요청이 통과시키지 않는다
- 쓰기 라우트에 `require_role(Role.ADMIN)` 연결, `app.state.auth_manager` 설정,
  JWT 에 `role` 클레임 추가
- AI Analyzer: `update_engine_config` / `reload_engine` 호출을 **소스에서 제거**,
  `apply_mode` 가 `propose` 가 아니면 생성 자체가 실패한다

---

## 4. 실행한 검증

```
tests/test_utils/test_support_contract.py         30 passed
tests/test_detection/test_config_validation.py    27 passed
tests/test_web/test_ui_output_safety.py           29 passed
tests/test_web/test_engine_config_write_policy.py 22 passed
tests/test_services/test_ai_write_isolation.py    15 passed
tests/test_services/test_ai_analyzer.py           43 passed  (기존 테스트를 새 계약으로 갱신)

전체 스위트   변경 전  1601 passed / 22 skipped
전체 스위트   변경 후  1724 passed / 22 skipped / 0 failed / 0 error
```

- 변경 후 스위트가 실패 0건이므로 Stage 1 이 기존 동작을 깨지 않았음을 확인했다.
- 브라우저 없이 `esc()` 계약을 검증하기 위해 Node 런타임에서 실제 함수를 실행해 확인했다.

  ```
  '<script>alert(1)</script>' -> '&lt;script&gt;alert(1)&lt;/script&gt;'
  'x" onerror="alert(1)'      -> 'x&quot; onerror=&quot;alert(1)'
  "y' onerror='alert(1)"      -> 'y&#39; onerror=&#39;alert(1)'
  0                            -> '0'      (이전 구현은 빈 문자열이었다)
  false                        -> 'false'  (이전 구현은 빈 문자열이었다)
  ```

- **로컬 환경 주의 (저장소 설정과 무관)**: 저장소의 `.venv` 는 존재하지 않는
  `/home/nirna/anaconda3/bin/python3` 를 가리키는 죽은 링크다. 작업용 `.venv-new`
  (Python 3.13.13)를 만들어 검증했다. 테스트 DB 는 `bee/bee@localhost:35432` 로
  기동했다(CLAUDE.md 의 기본값과 동일).

---

## 5. 이번에 하지 않은 것 (다음 실행 단위)

계획서 기준으로 남은 항목이며, 아직 코드에 반영되지 않았다.

| PR | 내용 | 비고 |
|-|-|-|
| PR 04~06 | 자동화 DB 배포 경로, 인시던트 ID, 영속성 | 게이트 G4/G6 |
| PR 07~08 | 위협 피드·엔진 수명주기, 탐지 결과 계약(요약→근거→원자료) | 게이트 G1/G8 |
| PR 09~11 | 증거 봉투, 리플레이·후보 diff, 관측 범위 UI | 게이트 G2 |
| PR 12~16 | nftables 실구현, 문서·교육·거버넌스 | 게이트 G7 |

특히 다음 두 항목은 Stage 1에서 **의도적으로 미구현**했다.

1. **거부 경고의 닫힌 루프** — 이제 위반이 400/기동 실패로 드러나지만, 위반을 운영자가
   볼 수 있는 대시보드 화면은 아직 없다. `/api/support-profile` 응답만 노출된 상태다.
2. **승인 큐** — AI 제안(`status=proposed`)이 이벤트로 쌓일 뿐, 이를 승인해 설정에
   반영하는 경로는 아직 없다. 계획서의 "읽기/제안/승인 3역할"에서 승인 단계를 실제로
   채우려면 이 큐와 그 UI 가 필요하다.

---

## 6. 게이트 러너와 실측에서 나온 추가 결함 (PR 01 CI 계약 / PR 04)

`scripts/gates.py` 를 추가해 G0 게이트를 실행 가능하게 만들었다. 이 러너가
**처음 실행했을 때 실제로 실패했고, 그 실패가 진짜 결함 두 개를 드러냈다.**

```
python scripts/gates.py                 # 전체 게이트
python scripts/gates.py --gate G0-1     # 특정 게이트만
python scripts/gates.py --json          # CI 용
```

| 게이트 | 내용 | 상태 |
|-|-|-|
| G0-1 | 지원 프로필 계약 | PASS |
| G0-2 | AI 쓰기 격리 (AST 검사) | PASS |
| G0-3 | 안전한 UI 출력 (정적 검사) | PASS |
| G0-4 | DB 마이그레이션 head 적용 | PASS (수정 후) |
| G0-5 | 회귀 스위트 | PASS |

게이트는 "맞았는지"가 아니라 "배포해도 되는지"만 판정한다. 그래서 DB 가 없으면
G0-4 를 실패시키고, 설정 검증 통과를 enforcement 통과로 취급하지 않는다.

### 게이트 G0-4 가 드러낸 결함: 깨끗한 DB 에서 마이그레이션이 실패한다

`alembic/versions/008_events_monthly_partitioning.py` 는 **한 번도 성공적으로 실행된
 적이 없다** 고 해당 커밋의 메시지가 스스로 인정한다. 실제로 처음 실행해 보니 두 가지
결함이 있었다.

1. `conn.execute("SELECT ...")` 로 원시 문자열을 넘김 → SQLAlchemy 2.x 에서
   `ObjectNotExecutableError` 로 즉시 실패. 조회에는 `text()`,
   DDL/DML 에는 `op.execute()` 를 쓰도록 고쳤다.
2. **더 심각한 것** — 재생성한 `events` 의 컬럼 순서가 `events_old` 와 달랐다.
   `INSERT INTO events SELECT * FROM events_old` 는 *위치*로 대응시키므로
   `title_key ← metadata`, `reasoning ← resolved` 처럼 값이 조용히 뒤섞였다.
   대응 컬럼 목록을 `EVENTS_COLUMNS` 로 명시했다.

수정 후 실측:

```
alembic upgrade head                        # 001 → 009 정상 완료
alembic downgrade 007_devices_host_labels   # 역방향 정상
(구분 가능한 값으로 데이터 1건 삽입)
alembic upgrade head                        # 재파티셔닝
→ engine=sig, reasoning=why-it-fired, title_key=events.signature.title,
  description_key=events.signature.desc, mitre_attack_id=T1071, threat_level=3
  전부 원래 위치에 보존됨
```

회귀 가드는 `tests/test_utils/test_migrations.py` 에 두었다: 원시 문자열 `conn.execute`
금지, `INSERT ... SELECT *` 금지, revision 사슬 무결성, 파티션 키 포함 여부.

---

## 7. PR 05~06: 인시던트 식별자와 영속성 (게이트 G4/G6)

두 번째 실행 단위에서 **실측으로 결함 두 개를 더 찾아 수정했다.**

### PR 05 — 인시던트 id 가 두 개 공간에 존재했다

`AlertCorrelator` 가 `self._next_id` 인메모리 카운터로 `Incident.id` 를 만들고,
`_persist_create()` 는 `repo.insert()` 의 `RETURNING id` 를 **버렸다.** 즉 DB 는
자기 시퀀스로 다른 id 를 부여하고 있었다.

```
기동 1회차: 인메모리 1,2,3…   DB 1,2,3…   → 우연히 일치 (그래서 발견이 안 됨)
재시작 후:  인메모리 1,2,3…   DB 41,42,43… → 어긋남
```

어긋난 뒤 실제 발생하는 일:

- `POST /api/incidents/{id}/resolve` (대시보드는 저장소 id 를 봄) → 상관분석기는
  **과거 인시던트를** 해결 처리한다
- `_persist_update(incident_id=incident.id)` → `UPDATE incidents SET ... WHERE id = $1`
  이 **무관한 인시던트의** severity·alert_ids·engines 를 덮어쓴다 (조용한 데이터 손상)

수정: id 의 단일 정의를 **DB** 로 모았다.

- `Incident.id: int | None` — 삽입이 끝날 때까지 `None`
- `_next_id` 카운터 삭제
- `async_process_alert()` / `persist()` 추가 — 디스패처가 await 해서 **DB 가 부여한
  id 를 갖는 인시던트**를 받는다. WebSocket·대시보드·DB 가 같은 id 를 보게 된다
- `resolve_incident()` / `get_incident()` 는 id 가 `None` 인 인시던트를 조회 대상에서
  제외한다
- `to_dict()` 에 `persisted` 플래그 추가

회귀 가드: `tests/test_detection/test_incident_identity.py` (13개) — 재시작 충돌,
멱등 삽입, 업데이트/해제 대상 id, 저장소 장애 시 id 미부여, 카운터 부재 소스 검사.

### PR 06 — 종료 시 큐에 남은 알림이 버려졌다

`AlertDispatcher.stop()` 이 소비자를 **즉시 cancel** 해서, 큐(maxsize 10000)에 쌓인
알림을 DB 미저장·미브로드캐스트·미차단 상태로 버렸다. 버스트 중 종료하면 그만큼의
탐지 결과가 조용히 사라진다. 게다가 소비 루프가 `task_done()` 을 호출하지 않아
`queue.join()` 이 영원히 진행되지 않았다.

수정:

- `stop()` 이 먼저 `queue.join()` 으로 배 emptiness한 뒤 소비자를 취소
- `drain_timeout_seconds` (기본 5초) 로 무한 대기 방지, 초과 시 남은 개수를 경고
- 소비자가 시작되지 않은 구성에서는 큐를 직접 비우고 경고
- 소비 루프에 `task_done()` 을 `finally` 로 보장 (처리 실패가 배 emptiness를 막지 않음)

회귀 가드: `tests/test_alerts/test_dispatcher_durability.py` (10개). **이 테스트를
이전 구현에 되돌려 실제로 전부 실패하는 것을 확인했다.**

```
이전 stop() 적용 시:  10 failed
수정 후:              10 passed
```

### CI 워크플로

`.github/workflows/gates.yml` — 게이트 러너를 CI 로 강제한다.

- `gates` 잡: PostgreSQL 서비스 + `alembic upgrade head` 후 `python scripts/gates.py`
- `db-deploy-check` 잡: 깨끗한 DB 에서 `upgrade head` → `downgrade -1` → `upgrade head`
  왕복 + 마이그레이션 정적 가드

로컬에서 CI 와 동일한 명령을 재현해 통과를 확인했다.

```
alembic downgrade -1        OK
alembic upgrade head        OK
tests/test_utils/test_migrations.py  22 passed
```

### 현재 검증 상태

```
전체 스위트   1770 passed / 22 skipped / 0 failed
게이트        5/5 통과
```

---

## 8. PR 07: 위협 피드 생애주기 — 가장 나쁜 실패 형태를 막다 (게이트 G1/G8)

세 번째 실행 단위에서 **감시 도구가 조용히 그만 보는 실패**를 찾아 막았다.

`FeedManager.update_all()` 은 갱신 **전에** 라이브 집합을 비웠다.

```python
self._blocked_ips.clear()      # ← 갱신 전에 먼저 비운다
self._blocked_domains.clear()
...
await asyncio.gather(...)      # ← 이 사이에 네트워크가 끊긴다
self.last_update_epoch = time.time()   # ← 무조건 "갱신됨"
```

네트워크가 끊기면 실제 결과는 이렇다:

| | 값 |
|-|-|
| threat_intel 엔진이 보는 지표 | **0건** |
| `last_update_epoch` | 방금 갱신된 것처럼 표시 |
| Prometheus `feed_last_update` | 방금 갱신된 값 |
| 운영자가 아는 것 | 아무것도 모름 |

탐지가 멈춘 것과 탐지가 없었다는 것이 구분되지 않는다. 감시 도구가 **조용히 아무것도
보지 않는 상태**는 오탐보다 나쁘다.

추가로 `_feed_refresh_loop()` 은 `asyncio.sleep(interval)` 이 먼저였으므로, 기동 후
첫 갱신이 6시간 밀려 있었다. 그 사이 threat_intel 은 빈 목록으로 돈다.

수정:

1. **원자적 교체** — 새 상태를 별도 `_FeedAccumulator` 에 쌓고, 실제 성공한 뒤에만
   라이브 집합을 교체한다
2. **실패해도 기존 상태 유지** — 아무 피드도 콘텐츠를 제공하지 못하면 기존 차단 목록을
   그대로 두고 갱신 실패로 기록한다
3. **`last_update_epoch` 은 실제 성공 시에만 전진** — 건강 신호가 거짓말하지 않는다
4. **정직한 신선도 보고** — `feed_health()` / `is_stale()` / `health_as_violations()`
   가 "작동 중" 과 "지표가 최신" 을 구분한다
5. **기동 직후 첫 갱신** — 잠그기 전에 갱신한다
6. **주기 정규화** — 0 이하거나 잘못된 주기는 최소 60초로 올려 busy loop 를 막는다
7. `/api/support-profile` 이 `feeds` 상태와 정체 사유를 함께 노출한다

회귀 가드: `tests/test_threatintel/test_feed_lifecycle.py` (15개). 이전 구현으로
되돌려 실제로 실패하는지 확인했다.

```
이전 동작 적용 시: 4 failed (전체 실패 시 지표 소실 / 시간 전진 / 커스텀 항목 소실)
수정 후:          15 passed
```

게이트 G0-6 을 추가했다: 갱신 전 라이브 상태 삭제 금지, 신선도 보고 함수 존재,
갱신이 잠금보다 먼저인지 정적으로 확인한다.

---

## 9. PR 08: 탐지 결과 계약 — 요약 → 근거 → 원자료 (게이트 G8)

`netwatcher/detection/evidence.py` 로 세 층을 판정하고 **기록**한다.

| 층 | 판정 기준 |
|-|-|
| 요약 | 제목이 있고, 설명·근거 중 하나 이상 |
| 근거 | `metadata` 에 관측값이 있거나 `reasoning` 이 있음 |
| 원자료 | `packet_info` 에 레이어 또는 길이가 있음 |

설계 판단이 하나 중요하다. **누락이 있어도 저장을 막지 않는다.** 대신
`metadata["evidence"]` 에 상태를 남겨 "근거 없는 탐지"를 필터링할 수 있게 한다.
근거 없는 알림을 조용히 지어내는 것은 감사에 가장 위험하므로 절대 하지 않는다.
그랬다면 계약이 아니라 위장이 된다.

특정 판정 하나: **`confidence` 만으로는 근거가 아니다.** 그 값은 디스패처가
저장을 위해 나중에 붙이는 값이라 "왜 그렇게 판단했는가" 를 설명하지 못한다.
이걸 근거로 인정하면 계약이 표면적으로만 채워진다.

### 실측에서 확인한 사실

25개 엔진 중 `packet_info` 를 직접 채우는 엔진은 **0개**다. 원자료 층은
`PacketProcessor._run_engines_local` 이 중앙에서 채운다. 즉 계약을 엔진이
지키는 것이 아니라 **파이프라인이 지킨다.** 이 공백을 계약이 감추면 오히려
해롭다. 테스트는 이 지점을 명시적으로 고정한다.

```
알림 파이프라인을 거치지 않으면 → missing=["raw"] 로 드러난다
파이프라인을 거치면           → 세 층 모두 충족
```

회귀 가드: `tests/test_detection/test_evidence_contract.py` (17개). 실제 포트 스캔
엔진에 SYN 패킷 10개를 흘려 얻은 **실제 알림**으로 검증한다(합성 딕셔너리 아님).

게이트 G0-7: 계약 함수 존재 + 디스패처가 실제로 적용하는지 정적 확인.

---

## 10. PR 09: 증거 봉투를 실제로 보이게 만들기 (게이트 G2)

PR 08 에서 만든 계약이 **아무도 볼 수 없는 상태**였다. `metadata["evidence"]` 는
Technical Metadata JSON 안에 파묻여 있었고, 검토자는 "이 탐지가 검증 가능한가" 를
한눈에 알 수 없었다. 계획서의 관측 범위 UI 전제가 여기서부터 시작된다.

### API: 읽을 때 다시 판정한다

이벤트 API(`/api/events`, `/api/events/{id}`)가 봉투를 계산해 함께 돌려준다.
중요한 판단 하나는 **저장된 판정을 신뢰하지 않는다**는 것이다.

```
저장값: {"status": "complete", ...}   ← 계약 이전 행이 "complete" 라고 주장
실제 내용: metadata 에 근거 없음
→ 재생성 결과: incomplete
```

저장값을 그대로 노출하면 검증 불가능한 탐지가 검증 가능하다고 표시되는
역방향 오류가 생긴다. 계약이 UI 에만 있고 판단이 없는 셈이 된다.

### UI: 세 층을 명시적으로 그리고, 없는 층은 숨기지 않는다

`renderEvidenceEnvelope()` 가 요약·근거·원자료를 각각 사람이 읽는 말로 그린다.
근거가 빠진 탐지는 눈에 띄는 배너 + `"없음"` (취소선)으로 표시한다. 없는 근거를
지어내는 것보다 정직한 누락이 낫다.

Node 로 실제 렌더러를 실행해 확인했다(브라우저 없이):

```
complete → data-status="complete" + 세 층 모두 data-present="yes"
partial  → data-status="incomplete" + "검증 근거가 빠졌습니다: 근거, 원자료"
hostile  → <img src=x onerror=alert(1)> 이 &lt;img ...&gt; 로 이스케이프됨
```

회귀 가드: `tests/test_web/test_evidence_envelope_api.py` (12개) +
`tests/test_web/test_ui_output_safety.py` 에 봉투 렌더러 검사 추가(총 31개).

---

## 11. PR 10: 승인 루프 — "승인" 을 실제로 만든다 (게이트 G8)

PR 03 으로 AI 의 설정 쓰기 권한을 제거했다. 그런데 **제안 자체가 처리될 방법이
없었다.** 이벤트로만 기록되고, 반영할 수도 되돌릴 수도 없는 로그가 되었다.
계획서의 "읽기 / 제안 / 승인 3역할" 중 승인 단계를 비워둔 셈이었다.

### 마이그레이션 010: config_proposals

승인 대상이 사라지지 않고 감사 가능해야 하므로 저장 계층이 필요했다.

```
status ∈ {pending, approved, rejected, failed}
before        ← 승인 시점의 이전 설정 (되돌리기 근거)
applied/error ← 승인 후 실제 반영 결과
decided_by    ← 누가 승인했는가
```

`applied` 를 `status` 와 분리한 것이 중요하다. "승인됐지만 반영은 실패했다" 는
실제로 벌어지는 상태이고, 이 둘을 합치면 실패가 성공으로 보이게 된다.

### 제안 서비스의 원칙

1. **제안할 때 검증한다** — 스키마를 어기는 제안은 큐에 들어가지도 못한다
2. **승인만이 쓴다** — 반영 경로는 대시보드 설정 쓰기와 **동일**하다
   (검증 → `reload_engine` → YAML 기록). 별도 경로를 만들면 그 경로가
   검증과 권한을 우회하는 구멍이 된다
3. **승인 시점에 다시 검증한다** — 접수와 승인 사이에 다른 사람이 설정을
   바꿀 수 있으므로, 그 사이 스키마를 어긴 값이 섞여 있을 수 있다
4. **실패를 숨기지 않는다** — 반영 실패는 `status=failed` + 사유로 남긴다
5. **되돌릴 근거를 남긴다** — 승인 시점 설정을 `before` 에 저장한다

### 역할 분리 (HTTP 경계에서 검증)

| 동작 | viewer | analyst | admin |
|-|-|-|-|
| 목록 조회 | O | O | O |
| 제안 접수 | X | O | O |
| 승인 / 거절 | X | X | O |

승인은 곧 설정 쓰기이므로 ADMIN 이 필요하다. 제안 권한과 승인 권한을 분리한 것이
3역할 모델의 핵심이다.

### AI 연결

`AIAnalyzerService` 는 승인 큐가 주입되면 제안을 함께 접수한다. 큐가 없으면
기존처럼 이벤트 로그로만 남는다(테스트 호환).

회귀 가드: `tests/test_detection/test_proposal_queue.py` (16개) +
`tests/test_web/test_proposals_api.py` (14개). 게이트 G0-8 은 승인 엔드포인트,
ADMIN 요구, 승인 시 재검증, 저장 계층 존재를 정적으로 확인한다.

---

## 12. PR 11: 관측 범위 화면 — 계약을 대시보드에 닿게 하기 (게이트 G2)

PR 01 과 PR 10 까지 만든 것은 전부 **API 만 있었다.** 대시보드에서 확인할 수 있는
방법이 없었고, 승인하려면 curl 을 써야 했다. 계약이 화면에 닿지 않으면 장식이다.

`governance.js` + Governance 탭으로 두 가지를 한 화면에 모았다.

1. **무엇을 하는 도구인가** — 지원 프로필, 검증된 enforcement 백엔드, 위반 목록,
   위협 피드 신선도
2. **무엇을 바꿀 수 있는가** — 대기 중인 제안과 승인/거절

### 화면에서 일부러 거짓말하지 않는다

| 상태 | 화면 |
|-|-|
| 계약 위반 있음 | 노란 경고 + 위반 표 + "이 상태로는 배포하지 마세요" |
| 계약 위반 없음 | "운영 검증을 통과했다는 뜻이 아니다" 를 굵게 명시 |
| 피드 정체 | `stale` + 경과 시간, "한 번도 갱신 안 됨" |
| 승인됐으나 반영 실패 | "승인됨 · 반영 실패" (초록으로 칠하지 않는다) |

특히 "계약 통과 = enforcement 통과 아님" 문구는 계획서 G0 게이트의 취지와
동일하다. 이 문구가 없으면 대시보드는 그 자체로 검증 위장이 된다.

승인은 `window.confirm` 으로 한 번 더 묻는다. 승인 = 설정 쓰기이고, 임계값이
너무 낮아지면 오탐이 늘어난다. 되돌리려면 감사 로그를 뒤져야 한다.

### 테스트 방식

대시보드는 브라우저가 없으면 실행되지 않는다. 그래서 두 층으로 나눴다.

- **Node 로 실제 렌더러 실행** — `renderSupportProfile()` 를 실제 API 페이로드로
  돌려 출력 문자열을 검사한다 (위반 노출, 정체 표시, 이스케이프)
- **정적 계약 검사** — 탭 등록, 라우팅, 스타일, i18n 키, 토스트 severity 존재

Node 가 없으면 첫 번째 층만 skip 되고 두 번째 층은 항상 돈다. 이 테스트가
토스트 severity 를 스타일시트와 대조해서 잡았다 — 프로젝트에 `toast-success` /
`toast-error` 가 없고 실제 정의는 `info` / `warning` / `critical` 뿐이었다.

회귀 가드: `tests/test_web/test_governance_ui.py` (16개). 게이트 G0-9 는
탭·라우팅·두 API 경로·위반/실패 노출·안전한 출력을 정적으로 확인한다.

---

## 13. 노예(canary) 검증 — 실경로 종단간 테스트

계획서의 수락 순서는 **게이트 → 노예 → 운영** 이다. PR 11 까지 모든 검증이
컴포넌트 단위였다. 모킹된 저장소, 직접 만든 패킷, 라우터를 거치지 않은 호출.
노예 단계가 비어 있었다.

`tests/test_integration/test_canary.py` 는 모킹을 쓰지 않는다.

- 실제 PostgreSQL (테스트 스키마)
- 실제 엔진 (`EngineRegistry.discover_and_register()`)
- 실제 `AlertDispatcher` (큐 + 소비 루프 + 종료 배 emptying)
- 실제 HTTP 라우터 (JWT 역할 검증 포함)
- 실제 `EventRepository` / `ConfigProposalRepository`

검증 내용은 두 가지다. **첫 탐지 결과가 감사 가능한가**, 그리고 **승인 루프가
실경로에서 동작하는가.**

### 노예가 실제로 잡은 결함 2개

**1. `config_proposals` 가 마이그레이션에만 있었다**

`Database.connect()` 는 `ALL_SCHEMAS` 를 실행하는데, 그 목록에 이 테이블이
없었다. 즉 **테스트 스키마에서 저장소가 실행된 적이 한 번도 없었다.**
PR 10 의 저장소 테스트는 전부 FakeRepo였다. 스키마 정의에 추가하고,
두 정의가 어긋나지 않는지 검사하는 테스트를 넣었다.

**2. 내가 만든 승인 로직의 설계 결함 (더 심각)**

승인 시점에 **병합 결과 전체**를 검증했다. 그런데 `config/default.yaml` 에는
스키마에 없는 키(방치된 키)와 빠진 필드가 실제로 남아 있었다. 결과는:

```
승인 시도 → 400 "승인 시점 검증 실패 (3건)"
         → cooldown_seconds: 스키마에 선언되지 않은 키
         → stealth_threshold: 필수 설정 누락
         → internal_multiplier: 필수 설정 누락
```

**어떤 제안도 영영 승인될 수 없는 상태였다.** 제안자는 자기 제안을 고칠 수 없고,
큐가 영구히 막힌다. 내가 PR 03 에서 "기존 YAML 이 이미 어긋나 있으면 새 요청이
통과시키지 않는다" 고 의도적으로 넣은 규칙이, 다른 경로에서는 실제 결함으로
펑족한 셈이다.

수정 — 검증 대상을 나눈다:

| 대상 | 처리 | 이유 |
|-|-|-|
| 승인하려는 변경(params) 위반 | **거부** | 승인 대상이 스키마를 어기면 안 된다 |
| 기존 설정(before)의 부적합 | **경고로 노출, 차단하지 않음** | 고치는 것은 이 승인의 범위가 아니다 |

`Decision.warnings` 로 드러내므로 숨겨지지 않는다. 대시보드 설정 쓰기
(PUT /engines/{name}/config) 는 계속 병합 결과까지 차단한다 — 거기서는 사용자가
그 설정을 직접 편집하는 중이므로 문제를 같은 화면에서 고칠 수 있기 때문이다.
두 경로가 다른 것은 의도적이다.

### 테스트 방식에서 배운 것

`TestClient` 로 실제 asyncpg 풀을 쓰는 라우터를 호출하면 실패한다.

```
asyncpg.exceptions.InterfaceError: cannot perform operation: another operation is in progress
```

`TestClient` 은 앱을 **별도의 이벤트 루프**에서 실행하는데 asyncpg 커넥션은
루프에 묶여 있다. 실제 DB 를 통과시키는 검증에는 같은 루프의
`httpx.ASGITransport` 가 필요하다. 모킹 기반 테스트에서는 문제가 되지 않던
차이여서, 실경로 검증 없이는 발견할 수 없었던 종류의 오류였다.

---

## 14. PR 11 을 마무리하기: 관측 범위 계측을 실제로 배선하기 (계획서 3장)

12 절의 거버넌스 화면은 **계약**을 보여준다. 하지만 그 화면이 말하는
"관측됨" 이라는 단어를 뒷받침할 계측이 없었다. 화면만 있고 측정값이 없으면
그 화면은 장식이 아니라 오독 장치다.

### 계측이 없으면 판정은 통과가 된다

`netwatcher/observability/observation.py` 는 만들어져 있었지만 아무 데서도
불리지 않았다. 배선이 없는 상태에서 `snapshot()` 은 모든 카운터가 0 인 창을
그대로 "관측됨" 으로 보고한다. **아무것도 보지 않았는데 멀쩡하다고 말하는 것.**

그래서 계측 지점을 실제로 꽂았다. 계획서 3 장이 지목한 그대로:

| 단계 | 계측 지점 | 무엇을 세는가 |
|-|-|-|
| capture | `capture/sniffer.py` | NIC 로 들어온 패킷, 커널 drop |
| input_queue | `capture/sniffer.py` | 배압 버퍼 통과량과 **앱** drop |
| engine | `services/packet_processor.py` | 엔진이 받은 패킷과 낸 경보 |
| result_queue | `alerts/dispatcher.py` | 알림 큐 유입과 큐 포화 drop |
| db | `alerts/dispatcher.py` | 실제 저장 성공/실패 |
| alert | `alerts/dispatcher.py` | 억제(속도 제한)와 방출 |

heartbeat 는 `tick_service` 1초 틱이 매번 찍는다. 10초 주기에서 3회 이상
오지 않으면 `stale` — 즉 **센서가 살아 있는지 확인되지 않으면 경보 부재를
근거로 쓸 수 없다.**

### 계획서가 "측정 불가"라 한 것 중 실제로 측정 가능한 것이 있었다

계획서는 "NIC/스위치 손실은 측정 불가능하므로 unknown" 이라고 한다. 이건
맞다 — 그래서 `loss.link_loss` 는 값 없이 사유만 갖는다.

그런데 **커널 버퍼 drop 은 측정 가능하다.** `/proc/net/softnet_stat` 의 2번째
필드를 읽으면 된다. 이를 `unknown` 으로 덮으면 측정 가능한 값을 버리는 셈이므로
`KernelDropProbe` 로 별도 계측한다. 단, 이 값은 앱 관측창의 분모와 시점이
다르므로 `app_loss_ratio` 에 절대 포함하지 않는다.

```
앱 손실률 = 앱 drop / 같은 단계·같은 시간창의 수신
커널 drop  = 따로 본다. 합산하지 않는다. 합치면 의미 없는 숫자가 된다
링크 손실  = unknown. 숫자를 만들지 않는다
```

### 고속 경로에서 계측이 본체가 되지 않게 하기

패킷마다 잠그고 `time.time()` 을 부르면 계측이 측정 대상이 된다. 그래서
스니퍼 스레드에 합산만 해 두고 asyncio 루프의 배출 시점에 한 번에 반영한다.

```python
# _on_packet (스니퍼 스레드): 합산만
# _drain_buffer (이벤트 루프): 스왑 후 반영
```

스왑 중 도착한 패킷이 유실되지 않는지도 테스트로 고정했다
(`test_flush_never_loses_counted_packets`). 과대 계상도, 과소 계상도 없다.

### "경보 없음" 을 가릴 수 있던 두 경로를 막다

계측을 실제로 붙이면서 드러난 결함 두 가지가 있었다. 둘 다 "조용한 성공" 이다.

1. **DB 저장이 실패해도 아무 흔적이 없었다.** 경고 로그는 남지만 계측에는
   남지 않았다. 이제 `db` 단계 drop 으로 기록한다. DB 가 죽은 채로 "경보가
   없다" 가 되어도 드러난다.
2. **속도 제한으로 막힌 경보가 손실로도 억제로도 세어지지 않았다.** 이제
   `suppressed` 로 따로 센다. 억제는 손실이 아니므로 손실률에 들어가지 않는다.

### 내가 처음 만든 구현이 틀렸던 두 곳

테스트가 잡았다. 문서화해 둔다.

| 결함 | 왜 문제인가 | 수정 |
|-|-|-|
| 손실 항목에 분모가 없었다 | 백분율만 떼어 보면 무엇에 대한 비율인지 모른다 | `received` 를 숫자 옆에 둔다 |
| 정상 상태에서 `reasons` 가 비었다 | 상태는 항상 이유를 동반해야 하는데, API 는 빈 근거를 보고 `unknown` 으로 낮춘다 — **정상 센서가 unknown 으로 표시**될 뻔했다 | 근거가 없으면 "관측 창에 이상이 감지되지 않았다" 를 명시 |

두 번째가 더 위험했다. "판정 없는 상태를 만들지 않는다" 는 규칙을 어기면
오히려 **정상 상태가 오류로 보인다** —— 경보가 없는 상황에서 가장 나쁜 방향이다.

### 검증

- `tests/test_observability/test_observation_scope.py` — 계약 17건
- `tests/test_observability/test_observation_wiring.py` — 배선 10건
- `tests/test_web/test_observation_api.py` — API 11건
- `tests/test_web/test_governance_ui.py` — 실제 렌더러 5건 추가

배선 테스트는 **배선 이전 코드에서 10건 전부 실패**함을 확인했다
(`dispatcher.py` / `sniffer.py` 를 `d7c8dff` 상태로 되돌려 실행).

게이트 G0-10 은 계약 위반 세 가지를 실제로 잡아내는지 확인했다.

|고의로 깨뜨린 것 | 결과 |
|-|-|
| `dropped_app + dropped_kernel` 로 합산 | FAIL |
| 분모 없을 때 사유 문구 제거 | FAIL |
| 엔진 단계 계측 호출 삭제 | FAIL |

게이트를 처음 만들었을 때 "상수 import" 만 확인해서 계측 호출이 사라져도
PASS 했다. 실제 `.record(STAGE_...)` 호출이 있는지 보도록 고쳤고, 그 고친
버전으로 계측 삭제를 실험해 FAIL 을 확인했다. **검증하지 않은 게이트는
없다고 생각한다.**

---

## 15. PR 12: 오프라인 리플레이·비교 — "비교했다" 는 말의 조건 (계획서 1장)

    "기존/후보 예외를 같은 입력으로 비교한다."
    "재실행은 운영 Dispatcher 를 호출하지 않는다. 저장 바이트→파서→순수 분석→
     격리 결과 저장만 허용하며 NIC 주입·외부 DNS/피드 조회·알림·방화벽·
     운영 DB 쓰기는 차단된다."

이 장의 실질은 리플레이 기능이 아니라 **비교가 성립하는 조건** 이다.
그래서 저장 계층부터 세 개를 분리했다.

| 기록 | 무엇을 남기는가 | 없으면 |
|-|-|-|
| `evidence_records` | 그 판정이 무엇을 보고 어떤 버전에 근거했는가 | 비교 대상의 정체를 모른다 |
| `replay_traces` | 같은 입력을 되풀이할 수 있는 해시·순서·tick 일정 | "같은 입력" 이라는 말이 없다 |
| `replay_runs` | 두 버전의 결과 해시와 **비교 불가 사유** | 없는 지표를 비교 결과처럼 보인다 |

### 비교 불가는 실패가 아니라 결과다

`replay_runs.non_comparable_reasons` 를 컬럼으로 뒀다. 사유 없는 비교를
만들지 않기 위해서다. 사유 코드:

| 코드 | 뜻 |
|-|-|
| `trace_incomplete` | 입력이 잘렸다 — 같은 입력이 아니다 |
| `payload_engine_no_source` | 원본이 없다 — 해시·요약으로 대신하지 않는다 |
| `engine_not_supported` | G2·G3 를 통과하지 않은 엔진 |
| `version_scope_mismatch` | 버전 지문이 다르다 — 차이의 출처를 특정할 수 없다 |
| `feature_not_recorded` | 필요한 특징값이 기록되지 않았다 |
| `evidence_expired` | 근거가 만료됐다 |
| `budget_exceeded` | 실행 예산 초과 |

`GET /replay-runs/{id}/diff` 는 실행이 완료되지 않으면 diff 를 **내지
않는다**. 진행 중 결과를 비교하면 "비교했다" 고 말할 수 없기 때문이다.

### 격리는 주석이 아니라 게이트다

금지 목록을 `contract.py` docstring 에 적는 것으로는 부족하다. 주석은
약속이고 주석은 지워진다. 그래서 `scripts/gates.py` **G0-11** 이
`netwatcher/replay/` 전체를 AST 로 정적 검사한다.

- `netwatcher.alerts` / `response` / `capture` / `threatintel` /
  `utils.network` / `services` / `scapy` / `socket` / `httpx` import 금지
- `enqueue(` / `init_chain(` / `update_all(` 호출 금지
- `INSERT|UPDATE|FROM events|blocks|custom_blocklist` 금지

게이트가 실제로 잡는지 확인했다. Dispatcher import 를 심고 → FAIL,
`INSERT INTO events` 를 심고 → FAIL, 복원 → PASS.

### 세 엔진은 판정 엔진이 아니다

    "각 후보는 주소 바인딩 변화 · 연결 시도 분포 · 전송량 초과라는 관측
     의미를 표시한다. 악성 여부를 확정하는 엔진으로 포장하지 않는다."

그래서 결과 타입에 `malicious` 필드가 없다. 테스트로도 못 넣게 했다
(`test_observation_never_claims_malice`). 그리고:

> "정상 여부는 담당자 확인이며 경보 감소가 오탐 감소는 아니다"

diff 응답의 `interpretation.notice` 가 이 문구를 그대로 실는다. 관측이
사라진 경우에도 `removal_cause` 를 달아서 "재현 불가로 사라진 것" 과
"임계값 때문에 안 잡힌 것" 을 구분한다.

### 테스트가 잡은 설계 결함 하나

payload 엔진을 "미지원" 과 "재현 불가" 중 어디로 분류할지 내가 잘못
만들었다. 처음 코드는 지원 여부를 먼저 검사해서, 원본이 필요한
`http_suspicious` 가 "아직 지원 안 함" 으로 보고됐다. 둘은 다른 사실이다.

- **미지원** — 지원하면 되지만 현재 범위 밖
- **재현 불가** — 지원해도 원본이 없어 불가능 (해시로 대신할 수 없음)

검사 순서를 뒤집어 더 구체적인 사유를 먼저 내도록 고쳤다. 테스트가
먼저 실패했고, 그 실패가 설계 오류였다는 걸 보여줬다.

### 결정성

계획서 검수: "동일 trace 3 회, G3 는 20 회 결과 fingerprint 비교, 임의 ID
만 제외하고 경보 시점 · 순서는 유지".

- 동일 trace 3 회 → 동일 지문 (`test_three_runs_are_stable`)
- 같은 값·다른 순서 → **다른** 지문 (`test_record_order_changes_fingerprint`)
- `Observation` 에 `malicious` 같은 임의 ID 를 넣지 않아 제외 대상이 없다
- 시점(`observed_at`)과 순서(`seq`)는 지문에 포함

확대하려면 반복 횟수만 바꾸면 된다. 3 회 → 20 회는 값 하나다.

### 예산

동시 1개(`asyncio.Semaphore(1)`) · 10분 · 원본 256MB 상한. 초과하면
`status='aborted'` 로 끝나고 사유가 남는다. **중단 사실을 숨기지 않는다** —
조용히 성공한 것처럼 보이는 것보다 나쁘다.

### HTTP

`POST /replay-runs`(analyst, 202 즉시 반환) → `GET /replay-runs/{id}` →
`GET /replay-runs/{id}/diff`(viewer). 실행은 `asyncio.create_task` 로
나간다 — 무거운 작업을 요청 스레드에 두면 대시보드가 멈춘다.

DB 를 쓰는 라우터 테스트는 `TestClient` 로 돌리면 안 된다. 앱이 **별도
이벤트 루프**에서 실행되어 asyncpg 커넥션이 끊긴다
(`ConnectionDoesNotExistError`). 같은 루프의 `httpx.ASGITransport` 로
통과시킨다. 12 절에서 제안 API 에서 배운 것을 그대로 적용했다.

회귀 가드: `tests/test_replay/test_replay_contract.py`(39), 
`tests/test_web/test_replay_api.py`(13) — 후자는 **실제 PostgreSQL** 에서
돌며 "운영 events 행 수가 그대로인지" 를 직접 센다.

---

## 16. PR 13: 조치 생애주기 — "차단됐다" 고 말할 수 있는 조건 (계획서 2장)

    "ResponseAction 은 requested → applying → active_verified → expiring →
     expired_verified, 수동 취소의 removed_verified 와 failed/unknown 을 둔다."
    "unknown 을 성공이나 해제로 표시하지 않는다."

### 이번에도 만든 것은 기능이 아니라 조건이다

계획서의 이 장은 nftables 실구현을 요구하지만, 같은 장이 스스로 출하 기준을
정한다:

> "검증된 만료 백엔드·권한 분리·적용 경로 증명이 하나라도 없으면 shadow/제안만
> 출시한다."
> "기존 iptables 자동 차단은 복구 검증 전 계속 비활성화한다."

세 가지 중 **하나도** 없다. 그래서 이 PR 은 실차단 백엔드를 만들지 않았다.
만들었다면 "구현됨" 이라고 표시하면서 만료 복구를 증명하지 못한 채 운영에
놓는 셈이 된다. 그게 이 계획서가 가장 경계하는 일이다.

따라서 등록되는 실행기는 `ShadowExecutor` 하나이고, 그 결과는 항상
`unverified` / `observed: unknown` 이다.

### 승인과 적용을 나눈 이유

| 단계 | 뜻 | 실패해도 남는 것 |
|-|-|-|
| approve | 사람이 결정했다 | 결정 + TTL + 대상 + 해시 |
| activate | OS 에 넣었다 | 적용 의도 + 상태 + 만료 |

합쳐 두면 "승인됐으나 적용은 안 된 상태" 를 표현할 수 없다. 표현할 수 없는
상태는 결국 성공으로 뭉개진다. 분리하니 그 상태가 **존재하는 상태** 로 남는다.

`approved_hash` 는 대상·방향·TTL·scope 를 묶은 해시다. activate 시점에 그중
하나라도 다르면 409 다. 계획서:

> "승인 후 자산 매핑이나 scope 가 바뀌면 재승인한다."

### 재시도가 만료를 늘리지 않는다

`set_expire_once()` 는 `expire_at` 이 이미 있으면 그대로 반환한다. 재시도로
만료가 뒤로 밀리면 실제 노출 시간이 계획보다 길어지고, 그 사실을 아무도 모른다.

### 권한 분리

`ExecutionRequest` 의 필드는 다섯 개뿐이다 — 대상·방향·TTL·rule_tag·scope.
임의 명령을 받는 통로가 없다. 웹 라우터는 실행기를 **주입받으며** 직접
생성하지 않는다(게이트 G0-12 가 이걸 확인한다).

미구현 백엔드는 `UnavailableExecutor` 로 **명시적으로 예외를 낸다.** `None`
으로 남기면 호출자는 "설정 안 해서 안 하는 것" 과 "구현돼서 안 되는 것" 을
구분할 수 없다. 그래서 만든다.

### 조정 (재시작 대조)

`reconcile()` 은 DB 의 의도와 OS 의 사실을 대조한다.

| 관측 | 판정 |
|-|-|
| present (지문 일치) | `confirmed` |
| present (지문 불일치) | `mismatch` — 외부 관리자가 바꿨을 수 있음 |
| 만료됐는데 present | `mismatch` — **만료와 GC 회수를 분리** |
| absent | `absent` — 의도와 어긋남 |
| 확인 불가 | **`unknown`** — 존재/부재를 판단하지 않음 |

마지막 행이 이 장의 요지다. 확인하지 못한 것을 확인했다고 쓰지 않는다.
만료는 `expire_at` 로 판단하고, `expired_verified` 는 그 뒤 규칙이 실제로
없음을 조회해서 얻는다. **원소 수가 남았다는 이유만으로 차단이 지속된다고
판단하지 않는다.**

### 테스트가 잡은 것

`response_actions` 마이그레이션(012)만 만들고 `schemas.py` 의 `ALL_SCHEMAS`
에 넣지 않았다. 10 절에서 `config_proposals` 로 이미 한 번 겪은 불일치다.
테스트 DB 는 마이그레이션이 아니라 `ALL_SCHEMAS` 로 스키마를 만들기 때문에
테이블이 없었다. **같은 실수를 두 번 하는 것** 이 기록할 만한 사실이다.

### 게이트 G0-12 — 기능이 없음을 확인하는 게이트

이 게이트는 "조치가 작동하는가" 를 검사하지 않는다. **작동하지 않는 것을
확인한다.** 대시보드가 "적용됨" 을 보여주면 그건 방어 사례가 아니라 허위
표시이기 때문이다.

- 실행기가 `subprocess` / `os.system` / `Popen` / `nft ` 를 쓰면 FAIL
- `UnavailableExecutor` 표현이 없으면 FAIL
- 웹 라우터가 실행기를 직접 생성하면 FAIL (권한 분리가 아님)
- `config/default.yaml` 의 `response.enabled: true` 면 FAIL

각 항목별로 실제로 깨뜨려 FAIL 을 확인했다. 설정 구간 추출도 처음엔
`dns_response:` 에 잘려서 `enabled: true` 를 잘못 잡았다 — YAML 섹션을
줄 단위로 판정하도록 고쳤다.

회귀 가드: `tests/test_response/test_action_lifecycle.py`(35),
`tests/test_web/test_response_api.py`(16) — 후자는 실제 PostgreSQL.
노예 테스트에도 "적용됨을 주장하지 않는가" 를 추가했다.

---

## 17. PR 14: 최소 대응 제안 — 좁히지 못하면 제안하지 않는다 (계획서 4장)

    "제한을 좁힐 수 없으면 넓은 IP 차단으로 자동 대체하지 않는다."
    "응답 지연 시 캐시된 매핑으로 실행하지 않는다."
    "규칙 기반 제안기만 사용하며 AI 는 승인·scope·TTL 을 결정하지 않는다."

### 대체는 안전한 쪽이 아니다

"좁히지 못했으니 넓게 막자" 는 한 문장인데, 그 결과는 **정확한 대상이
아닌 것을 막는 것** 이다. 공유 IP·NAT 환경에서는 옆 회사의 장비가 함께
막힌다. 그래서 이 PR 은 대체 경로를 만들지 않았다. 좁힐 수 없으면
제안을 만들지 않고 409 로 끝낸다.

### 확인된 것과 확인되지 않은 것을 분리한다

`ResponseProposal` 은 `expected_assets`(확인됨)와 `unconfirmed_assets`
(확인 안 됨)를 **별도 컬럼** 으로 가진다. `/impact` 응답도
`observed_scope` / `unconfirmed_scope` 로 나눈다. 평균 내지 않고, 감추지
않고, 다른 칸에 둔다. 이게 이 장의 핵심이다.

### 제안 단계와 실행 단계의 기준이 다르다

오래된 매핑에 대해:

- **제안** — 만들되 `asset_mapping_stale` 불확실성으로 남긴다.
  "이 대상은 확인이 안 되었다"는 사실 자체가 정보다.
- **실행** — 거부한다 (409). `assert_mapping_fresh()`.

이 구분을 한 단계로 합치면 둘 중 하나가 틀린다. 제안에서 막으면 사람이
볼 정보를 잃고, 실행에서만 막으면 caches 로 실행될 수 있다.

`mapping_confirmed_at` 은 마이그레이션 014 로 `response_actions` 에 추가했다.
없으면 실행 시점에 "언제 확인했는지" 알 수 없어 규칙을 적용할 수 없다.

### AI 는 scope·TTL 을 결정하지 못한다

`build_proposal(created_by="ai")` 는 403 이다. 규칙 기반 제안기만 존재한다.

### 게이트 G0-13 — 세 번 반복된 실수를 막는다

`ALL_SCHEMAS` 누락이 **세 번** 발생했다. `response_actions`,
`response_proposals`, 그리고 앞서 `config_proposals`. 테스트 DB 는
마이그레이션이 아니라 `ALL_SCHEMAS` 로 만들어지기 때문에, 누락하면
**테스트는 통과하는데 그 테이블이 없다.**

주석으로는 막을 수 없다. G0-13 은 모든 마이그레이션의 `CREATE TABLE` 을
`ALL_SCHEMAS` 와 대조한다.

이 게이트를 만들면서 또 하나를 발견했다: 008 마이그레이션이 만드는
`events_backup` 은 같은 마이그레이션 안에서 사라지는 임시 테이블이다.
판정을 만들자마자 기존 결함을 잡았다. 다만 첫 판정에서 `downgrade()` 의
`DROP TABLE` 까지 보고해서 전체가 "일시적" 으로 판정되었고(15개 테이블인데
0개로 집계), `upgrade()` 본문만 보도록 고쳤다.

회귀 가드: `tests/test_response/test_minimal_proposal.py`(22),
`tests/test_web/test_response_proposals_api.py`(12) — 후자는 실제 DB.

### 문서

- `docs/OPERATIONS-GUIDE.md` — 운영자가 **하지 않는 것** 부터 적었다.
  보장하지 않는 것을 먼저 알아야 잘못된 확신을 갖지 않는다.
- `docs/GOVERNANCE.md` — 왜 이 코드가 이렇게 생겼는지. 원칙 8개와
  새 판단 로직 추가 시 체크리스트.

---

## 18. 전체 게이트 (G0-1 ~ G0-13)

| 게이트 | 이름 | 판정 |
|-|-|-|
| G0-1 | 지원 프로필 계약 | 이 설정으로 배포해도 되는가 |
| G0-2 | AI 쓰기 격리 | AI 가 설정·런타임·방화벽을 못 바꾸는가 |
| G0-3 | 안전한 UI 출력 | 렌더 경로에 실행 가능한 HTML/JS 가 없는가 |
| G0-4 | DB 마이그레이션 | head 가 실제 DB 에 적용되었는가 |
| G0-5 | 회귀 스위트 | 전체 테스트가 통과하는가 |
| G0-6 | 위협 피드 생애주기 | 지표가 최신인가, 아니면 말하는가 |
| G0-7 | 탐지 결과 계약 | 요약→근거→원자료 세 층이 있는가 |
| G0-8 | 승인 루프 | 사람이 승인한 것만 반영되는가 |
| G0-9 | 관측 범위 화면 | 계약이 대시보드에 닿는가 |
| G0-10 | 관측 범위 계약 | 계측 지점이 있고 손실률을 합산하지 않는가 |
| G0-11 | 리플레이 격리 | 운영 경로로 나가는 통로가 없는가 |
| G0-12 | 강제 주장 정직성 | OS 를 건드리지 않는데 적용됨이라 말하지 않는가 |
| G0-13 | 스키마 정합성 | 마이그레이션과 스키마 정의가 일치하는가 |

G0-11 · G0-12 · G0-13 은 **작동하지 않는 것을 확인하는 게이트** 다. 이
저장소에서 특히 중요하다. 기능이 없다는 것도 배포 판단의 일부이기 때문이다.

### 노예가 새 규칙에 걸린 것 — 좋은 신호

매핑 신선도 가드를 넣고 나서 노예 테스트가 실패했다.

```
KeyError: 'verified'
```

원인은 노예가 `mapping_confirmed_at` 없이 적용을 시도했다는 것이었다.
가드가 409 로 막았고, 응답에 `verified` 키가 없었을 뿐이다. **새 규칙이
실경로에서 실제로 작동한다는 뜻**이라 노예를 갱신했다. 그리고 노예에
매핑 미확인 → 409 검증을 명시적으로 추가했다 — 방어해야 할 것은 코드가
아니라 확인이다.

---

## 19. PR 15: nftables 실구현 — 커널 만료를 **실측** 한 경우에만 (계획서 2장)

13 절에서 "nftables 실구현은 하지 않는다" 고 적었다. 그 판단의 근거는
계획서 문장이었다.

> "검증된 만료 백엔드·권한 분리·적용 경로 증명이 하나라도 없으면 shadow/제안만
> 출시한다."

그리고 이 환경에는 `nft` 가 있고 `sudo` 로 root 를 얻을 수 있었다. 그래서
**검증을 먼저 해 볼 수 있었다.** 하지 않은 것이 아니라, 하지 않을 이유가
사라진 뒤에 구현한 것이다.

### 실측 결과 — 만료는 커널이 한다

격리된 네트워크 네임스페이스에서 직접 확인했다.

```
적용 직후:  elements = { 1.2.3.4 timeout 5s expires 4s994ms }
6초 후:     elements = { }
nft get element → rc != 0 (만료됨)
nft list set   → set 은 여전히 존재
```

마지막 줄이 이 계획서가 경계한 지점이다. **만료는 set 을 지우는 것이 아니라
원소를 지운다.** 그래서 "set 이 있다" 로 차단 지속을 판단하면 안 되고,
**잔여 원소 수** 로 판단해야 한다. `probe_kernel_expiry()` 가 세 조건을
모두 확인한다 — 만료 전 존재, 만료 후 부재, 잔여 원소 0.

```
$ sudo python -m netwatcher.verify_nftables
"expiry_verified": true,
"confirmed_present": true,
"confirmed_absent": true,
"detail": "만료 전 존재 확인 + 만료 후 부재 확인 + 잔여 원소 0"
검증 통과: 커널 측 만료가 확인되었다. (그래도 자동 차단은 기본 꺼짐)
```

### 구현한 것

`netwatcher/response/nftables_backend.py` — IPv4 input 전용 timeout set.
`inet nwwatcher` 라는 자기 테이블만 쓴다. `ip filter` 는 iptables-nft/ufw 가
관리하므로 **절대 건드리지 않는다**. flush 도 delete rule 도 없다.
주소·방향·TTL 외의 값은 실행기로 전달되지 않고, `subprocess` 는 argv
리스트에만 `shell=False` 로 쓴다.

### 그런데도 자동으로 켜지지 않는다

`kernel_expiry_verified` 는 **실측으로만** 참이 된다. 기동 시 자동 검증하면
라이브 장비의 방화벽에 우리 테이블이 남는 부작용이 생기므로, 검증은
운영자가 명시적으로 수행한다.

```
sudo python -m netwatcher.verify_nftables          # 격리 네임스페이스
sudo python -m netwatcher.verify_nftables --live   # 실제 장비
```

그리고 검증이 통과해도 `auto_block_enabled` 는 **false** 다. 백엔드가
구현되었다고 자동 차단을 켜는 건 계획서가 반대하는 것이다.

```
shadow    → applies_to_os=False  expiry=False  mode=shadow  auto_block=False
nftables  → applies_to_os=True   expiry=False  mode=shadow  auto_block=False
```

`mode` 가 shadow 인 이유가 `kernel_expiry_verified=False` 다. 백엔드가 있어도
쓰려면 사람이 검증해야 한다.

### 계획서 문장을 다시 읽어서 바꾼 것

> "현재 nftables 옵션은 미구현이며 재사용 가능한 완성 backend 로 간주하지
>  않는다."

이 문장은 **기존에 있던 미구현 옵션** 에 대한 것이었다. 그 옵션을 완성
backend 로reuse 하지 말라는 것이지, 새로 구현하지 말라는 것이 아니다. 그래서
새로 구현했다. `UnavailableExecutor` 는 모르는 백엔드(`ipfw` 등)에 대해
계속 예외로 알린다.

테스트 두 개가 이 상태 변화에 묶여 있어서 의도적으로 갱신했다
(`applies_to_os` false → true). 묶여 있던 계약을 조용히 바꾸지 않고
근거를 남기는 편이 낫다.

### G0-12 를 다시 썼다

"OS 를 건드리지 않는다" 는 검사에서 **"OS 를 건드릴 수 있는 모든 경로가
좁고 검증에 묶여 있는가"** 로 바꿨다. 규칙:

1. 웹 계약 모듈(`executor.py`)은 OS 를 직접 건드리지 않는다
2. 실제 백엔드는 argv 만 쓴다 (`shell=False`, `shell=True` 금지)
3. **생성되는 명령**을 검사한다 — 출처 정규식이 아니라 출력
4. 커널 만료 검증 진입점이 존재한다
5. 배포 설정이 자동 차단을 켜지 않는다

3번은 오탐을 피하려고 바꾼 것이다. 처음엔 출처에서 `ip filter` 를 찾았는데
docstring 에 "ip filter 를 건드리지 않는다" 고 **설명**해 둔 문장을 위반으로
잡았다. 검사 대상이 코드가 아니라 **생성되는 명령** 이어야 한다는 걸
실제로 배웠다.

세 가지 위반(호스트 테이블 참조 / flush 주입 / auto_block 활성화)을 각각
심어 FAIL 을 확인했다.

### 테스트에서 배운 것 두 가지

1. **`for line in sys.stdin` 은 파이프에서 멈춘다.** 읽기 선행 버퍼 때문에
   한 줄을 보내도 즉시 처리하지 않는다. 네임스페이스 헬퍼가 응답하지 않아
   "BrokenPipe" 로 죽었다. 줄마다 처리하려면 `readline()` 반복이어야 한다.
2. **격리 시험의 각 단계가 별도 네임스페이스를 쓰면 상태가 사라진다.**
   표와 set 을 만들었는데 다음 명령에서 없는 것처럼 보이는 상황이 발생했다.
   네임스페이스 하나를 프로세스로 열어 두는 방식으로 바꿨다. 반대로
   네임스페이스를 공유하면 테스트끼리 오염된다 — 하나만 만들고 그 안에서
   전부 수행한다.

### 아직 하지 않은 것

- **권한 분리(privilege separation)는 이 아키텍처에서 완전하지 않다.**
  실행기는 argv 를 좁게 받지만, 웹 프로세스에서 `sudo` 로 같은 권한을 얻는다.
  진짜 분리는 방화벽 권한이 없는 별도 프로세스/서비스가 필요한데, 이는
  단일 프로세스 배포 구조의 한계다. 이 문서를 읽는 사람은 이 한계를
  알고 있는 상태여야 한다.
- **G5 실경로 시험은 격리 네임스페이스에서만 돌렸다.** 실제 스위치에 붙은
  커널에서 장비별로 한 번 더 돌려야 한다. 그때 `--live` 를 쓴다.

### 편집 실수를 게이트가 잡았다

G0-12 를 통째로 다시 쓰면서 함수 사이 구간을 잘라냈고,
`_migration_upgrade_body` 가 사라졌다. G0-13 이 NameError 로 죽었다.

게이트는 **기능이 없음을** 검사하는데 자기 자신이 깨질 수 있다는 것도
드러내는 Instrument 역할을 한다. 아무도 그 테스트 파일을 열지 않아도
13번째 게이트가 즉시 실패했다.
