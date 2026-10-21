# 게이트 경험 라이브러리

관문은 "무엇을 지켰는가" 를 기억해야 한다. 같은 결함을 다시 흘려보내는 일은
관문 하나가 잡는 것보다 두 번 아프다. 이 파일은 **결함 유형 → 그 결함을 잡는
관문 → 근거** 를 남긴다.

`scripts/gates.py` 의 G0-20 이 이 파일을 읽는다. 규칙은 두 가지다.

1. 관문은 모두 이 파일에 결함 유형을 가져야 한다. 새 관문을 추가하고 이
   파일을 고치지 않으면 게이트가 실패한다.
2. 이 파일의 결함 유형은 모두 실제로 있는 관문을 가리켜야 한다. 관문 이름을
   잘못 적으면 게이트가 실패한다.

아직 관문으로 덮이지 않은 결함은 `uncovered` 에 **이유와 함께** 적는다.
숨지 않는다 — 덮이지 않은 채 남는 것이 보이는 것보다 나쁘다.

## 판독

```json
{
  "gates": {
    "G0-16": {
      "defects": ["events-partition-gap"],
      "evidence": "2026-10-20 실측: 008_events_monthly_partitioning 만 파티션을 만들어 3개월 뒤 INSERT INTO events 가 no partition of relation 으로 실패했다"
    }
  },
  "uncovered": [
    {
      "defect": "silent-exception-value",
      "reason": "유효한 형태의 실패 값을 돌려주는 함수가 남아 있다 — 5단계에서 정리한다"
    }
  ]
}
```

## 라이브러리

```json
{
  "gates": {
    "G0-1": {
      "defects": ["support-profile-violation"],
      "evidence": "2026-10-10 실측: response_execution·native.control 섹션이 없는 기본 설정에서 두 실행 모드가 시작 불가 상태였다"
    },
    "G0-2": {
      "defects": ["ai-write-isolation-gap", "write-surface-not-collected"],
      "evidence": "2026-10-10 실측: AI 제안 경로가 설정 쓰기 메서드를 부를 수 있었고, 금지 목록은 하드코딩이라 새 쓰기 표면을 놓쳤다"
    },
    "G0-3": {
      "defects": ["executable-inline-handler"],
      "evidence": "PR 02 실측: 대시보드 렌더 경로에 실행 가능한 인라인 핸들러가 들어갔다"
    },
    "G0-4": {
      "defects": ["migration-not-applied"],
      "evidence": "PR 04 실측: 깨끗한 DB 에 마이그레이션이 적용되지 않으면 이후 모든 검사가 표 부재로 흐려진다"
    },
    "G0-5": {
      "defects": ["regression", "test-database-target", "db-absent-error-not-skip", "schema-ddl-parity", "db-skip-contract-gap"],
      "evidence": "2026-10-20 실측: .env 가 시험 스키마를 가리켜 운영 DB 에 스키마를 만들고 지웠다. tests/test_utils/test_test_database_target.py 와 tests/test_utils/test_migrations.py 가 막는다. 2026-10-22 실측: psycopg2 직접 접속 시험 8개가 픽스처 이름 판정 밖에 있어 DB 부재 시 '건너뛰기' 가 아니라 '실패' 로 끝났다 — requires_db 마커로 판정을 넓혔다"
    },
    "G0-6": {
      "defects": ["feed-lifecycle-false-green"],
      "evidence": "PR 07 실측: 갱신 루프가 죽어도 지표는 살아 있어 아무것도 탐지하지 않는 상태를 놓쳤다"
    },
    "G0-7": {
      "defects": ["detection-contract-not-applied"],
      "evidence": "PR 08 실측: 판정 계약 함수가 있어도 디스패처가 부르지 않으면 근거 없는 경보가 그대로 배포됐다"
    },
    "G0-8": {
      "defects": ["approval-loop-break"],
      "evidence": "PR 10 실측: 제안이 큐에 들어가도 승인 방법이 없어 되돌릴 수 없는 기록만 남았다"
    },
    "G0-9": {
      "defects": ["observation-loss-hidden-in-ui"],
      "evidence": "PR 09 실측: 관측 손실이 화면에서 정상처럼 보였다"
    },
    "G0-10": {
      "defects": ["observation-contract-missing-denominator"],
      "evidence": "PR 09 실측: 분모 없는 커버리지와 0 을 정상으로 보이는 관측이 있었다"
    },
    "G0-11": {
      "defects": ["replay-touching-production"],
      "evidence": "PR 12 실측: 재실행이 운영 디스패처·방화벽·운영 events 에 닿으면 비교 결과가 거짓이 된다"
    },
    "G0-12": {
      "defects": ["enforcement-claim-without-contract"],
      "evidence": "2026-10-09 실측: 강제 실행이 계약 위반을 조용히 통과하며 성공으로 보고됐다"
    },
    "G0-13": {
      "defects": ["schema-migration-parity-gap", "test-only-table-in-schema", "table-undercount-by-constant-ddl"],
      "evidence": "PR 10 노예 검증 실측: 마이그레이션에만 있는 테이블이 테스트 DB 에 없어 검증 자체가 불가능했다. 2026-10-22 실측: ALL_SCHEMAS 의 events_default 는 마이그레이션이 만들지 않아 시험에서만 존재했다 — 시험은 범위 밖 INSERT 를 받아 주고 프로덕션은 막는다. 역방향 검사를 추가하고 마이그레이션이 상수를 참조하는 DDL 도 세게 했다 (표 32 → 37)"
    },
    "G0-14": {
      "defects": ["mutating-route-without-role-check", "gate-route-coverage-gap"],
      "evidence": "2026-10-10 실측: 게이트가 만드는 앱에 response·change-proposals 라우터가 없어 권한 누락이 검사되지 않았다"
    },
    "G0-15": {
      "defects": ["static-analysis-debt-slack", "lint-regression"],
      "evidence": "2026-10-10 실측: 상한이 실제보다 커서 빚을 갚아도 신호가 표현되지 않았다"
    },
    "G0-16": {
      "defects": ["events-partition-gap"],
      "evidence": "2026-10-20 실측: 008_events_monthly_partitioning 만 파티션을 만들어 3개월 뒤 INSERT INTO events 가 no partition of relation 으로 실패했다"
    },
    "G0-17": {
      "defects": ["prompt-contract-hidden-in-code-string"],
      "evidence": "2026-10-21 실측: 프롬프트가 코드 문자열이라 출력 형식 계약도 금지 어휘도 검사할 수 없었다"
    },
    "G0-18": {
      "defects": ["proposal-without-comparison-or-reason"],
      "evidence": "2026-10-21 실측: 승인 큐에 대비도 사유도 없는 제안이 들어가 판단자가 빈칸을 정상으로 읽었다"
    },
    "G0-19": {
      "defects": ["experience-without-evidence"],
      "evidence": "2026-10-21 실측: 근거 없는 교훈이 다음 제안의 판정을 망치는 길이 열렸다"
    },
    "G0-20": {
      "defects": ["gate-forgets-what-it-caught"],
      "evidence": "2026-10-21 실측: 관문은 자신이 잡은 결함을 기억하지 않았다 — 같은 결함이 다시 흘러갔다"
    },
    "G0-21": {
      "defects": ["web-layer-inversion", "layer-gate-bypass-by-filename"],
      "evidence": "2026-10-21 실측: 도메인 모듈이 netwatcher.web 를 가져와 센서 프로세스가 FastAPI 를 끌어들였다. 2026-10-22 실측: 예외 목록을 파일 이름으로 비교해서 netwatcher/response/runtime.py 같은 파일이 검사에서 통째로 빠졌다 — 파일 이름을 runtime.py 로 짓는 것만으로 계층 역전 게이트를 우회할 수 있었다. 예외를 상대경로로 비교한다"
    }
  },
  "uncovered": [
    {
      "defect": "dead-code-surplus",
      "reason": "사망 코드 약 4,411 LOC 가 남아 있다 — 5단계에서 정리한다"
    },
    {
      "defect": "dual-persistence",
      "reason": "에이전트 게이트웨이가 자체 SQLite 를 쓴다 — 5단계에서 정리한다"
    },
    {
      "defect": "event-loop-blocking-io",
      "reason": "위협 피드 매니저가 파일 읽기·쓰기를 이벤트 루프에서 한다 — 5단계에서 정리한다"
    },
    {
      "defect": "silent-exception-value",
      "reason": "실패를 유효한 형태의 값으로 돌려주는 함수가 남아 있다 — 5단계에서 정리한다"
    },
    {
      "defect": "type-check-baseline-not-measured-per-version",
      "reason": "mypy 는 CI 에서 래치로 돈다 (scripts/mypy_latch.py). 기준선은 Python 버전별이다 (scripts/mypy_baseline.json). 2026-10-22 실측: 3.13 은 190 으로 확인했지만 3.12 는 이 환경에 3.12 가 없어 확인하지 못했다 — 3.12 값은 이전 상한(196) 을 유지했다"
    },
    {
      "defect": "coverage-figure-not-reverified",
      "reason": "커버리지는 G0-5 에서 fail_under=80 으로 측정된다. '실측 84%' 는 DB 가 있는 상태의 수치다 — 2026-10-22 에 DB 없이 잰 63% 와 다르다. 새 실측값으로 갱신하지 않았다"
    },
    {
      "defect": "known-gap-hidden-as-skip",
      "reason": "DB 부재 skip 은 requires_db 마커로 명시적으로 구분된다 (2026-10-22). 그래도 환경 부재 skip 이 아닌 구현 미완 skip 이 남아 있을 수 있다 — xfail 로 더 구분해야 한다"
    },
    {
      "defect": "browser-test-silently-skipped",
      "reason": "브라우저 시험이 실제로 실행됐는지는 CI 가 scripts/assert_browser_ran.py 로 단언한다. 로컬에서는 Chrome 이 없으면 단언이 성립하지 않는다"
    },
    {
      "defect": "orphan-file-unreferenced",
      "reason": "참조되지 않는 최대 드라이버가 남아 있다 — 5단계에서 정리한다"
    },
    {
      "defect": "document-claim-drift",
      "reason": "문서의 revision·라우터·관문 수 주장이 코드와 어긋났다 — 사람이 관리한다"
    }
  ]
}
```
