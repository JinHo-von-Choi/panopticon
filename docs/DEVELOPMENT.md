# 개발과 기여

Python 코드는 `netwatcher/`, 대시보드는 `netwatcher/web/static/`, 시험 코드는 `tests/`에 있습니다. 기능을 수정하기에 앞서 관련 설정과 API, 기존 시험 내역부터 먼저 확인하십시오.

## 개발 환경

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-dev.lock
```

PostgreSQL에는 개발·시험용 DB를 따로 분리해 준비해야 합니다. 운영 DB를 대상으로 시험이나 성능 재현을 실행해서는 안 됩니다.

## DB 마이그레이션

스키마 변경 파일은 `alembic/versions/`에 추가합니다.

```bash
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic current
```

명령어는 `.env`와 환경변수에 지정된 DB를 대상으로 실행됩니다. 대상이 시험용 DB의 주소와 계정이 맞는지 반드시 먼저 확인하십시오. 아울러 빈 DB에 처음부터 끝까지 전체 적용이 잘 끝나는지, 그리고 직전 단계로 되돌렸다가 다시 적용하는 과정에 문제가 없는지도 검증해야 합니다.

## 시험

DB 시험을 진행할 때는 전용 접속 정보를 직접 지정해야 합니다.

```bash
export NETWATCHER_TEST_DB_HOST=127.0.0.1
export NETWATCHER_TEST_DB_PORT=5432
export NETWATCHER_TEST_DB_NAME=netwatcher_test
export NETWATCHER_TEST_DB_USER=netwatcher
export NETWATCHER_TEST_DB_PASSWORD='<시험 DB 비밀번호>'
export NETWATCHER_SKIP_DOTENV=1
.venv/bin/python -m pytest tests/ -q
```

건너뛴 시험 항목은 통과 수치에 포함하지 않습니다. 외부 서비스나 실제 네트워크 연동이 불가피한 검증 작업은 별도 격리 환경에서 진행하고, 당시 시험 조건을 누락 없이 기록해 두어야 합니다.

## 출시 검사

```bash
.venv/bin/python scripts/gates.py
```

게이트의 DB 검사 단계에서는 일반 `NETWATCHER_DB_*` 환경변수로 전용 DB를 지정한 뒤 마이그레이션을 마쳐 두어야 하며, DB 시험용 `NETWATCHER_TEST_DB_*` 역시 함께 잡아 주어야 합니다. 이 검사 과정에서는 로컬 `.env` 파일을 읽지 않습니다.

검사는 설정, 인증, 승인, 방화벽 명령, 마이그레이션, 회귀 시험 전반을 훑습니다. G0-14는 차단·목록·규칙·장치·엔진 변경 경로에서 관리자 권한 검사가 누락되었는지를 확인합니다. 실제 네트워크 처리량과 OS 차단 효과, 장시간 구동 시의 안정성은 게이트와 별개로 따로 검증해야 합니다.

## 변경 작성

직접 의존하는 패키지는 `requirements.txt` 및 `requirements-dev.txt`에 버전을 고정합니다. 배포와 시험 설치 환경에서는 전이 의존성과 배포 파일 해시까지 전부 묶어 둔 `.lock` 파일을 사용합니다. 의존성을 수정했다면 두 잠금 파일을 빠짐없이 갱신한 뒤 Python 3.12·3.13 환경에서 검증을 거치십시오. 갱신 명령은 각 잠금 파일의 첫머리 주석에 적혀 있습니다.

- 탐지 기능은 기존 엔진 인터페이스와 설정 검증 로직을 따릅니다.
- 대시보드는 기존 ES 모듈 구조와 한국어·영어 번역 체계를 그대로 사용합니다.
- 저장, 승인, 외부 전달 로직에서는 실패와 미확정 상태를 명확히 구분합니다.
- 사용법이 바뀌었다면 관련 가이드와 릴리스 노트를 함께 갱신해야 합니다.
- 비밀번호나 토큰, 원본 패킷, 특정 운영 환경에서 추출한 자료는 절대 커밋하지 마십시오.

PR 본문에는 풀고자 하는 문제와 변경 후 동작 방식, 검증 결과, 현재 파악된 제한 사항을 구체적으로 적어 주십시오. 상세한 검토 기준은 [기여 기준](GOVERNANCE.md) 문서를, 합성 성능 측정 방식은 [성능 시험 안내](../tests/performance/README.md) 문서를 확인하시면 됩니다.