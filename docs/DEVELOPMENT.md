# 개발과 기여

Python 코드는 `netwatcher/`, 대시보드는 `netwatcher/web/static/`, 시험은 `tests/`에 있습니다. 기능 수정 전에 관련 설정과 API, 기존 시험을 확인하세요.

## 개발 환경

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
```

PostgreSQL에는 개발·시험용 DB를 따로 준비합니다. 운영 DB로 시험이나 성능 재현을 실행하지 마세요.

## DB 마이그레이션

스키마 변경은 `alembic/versions/`에 추가합니다.

```bash
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic current
```

`.env`와 환경변수에서 지정한 DB에 적용됩니다. 시험용 DB의 주소와 계정인지 먼저 확인하세요. 새 DB의 전체 적용과 직전 단계의 되돌림·재적용을 확인합니다.

## 시험

DB 시험에는 전용 접속 정보를 지정합니다.

```bash
export NETWATCHER_TEST_DB_HOST=127.0.0.1
export NETWATCHER_TEST_DB_PORT=5432
export NETWATCHER_TEST_DB_NAME=netwatcher_test
export NETWATCHER_TEST_DB_USER=netwatcher
export NETWATCHER_TEST_DB_PASSWORD='<시험 DB 비밀번호>'
export NETWATCHER_SKIP_DOTENV=1
.venv/bin/python -m pytest tests/ -q
```

시험을 건너뛴 항목은 통과로 계산하지 않습니다. 외부 서비스나 실제 네트워크가 필요한 검증은 별도 환경에서 수행하고 조건을 기록합니다.

## 출시 검사

```bash
.venv/bin/python scripts/gates.py
```

게이트의 DB 검사에는 일반 `NETWATCHER_DB_*` 환경변수로 전용 DB를 지정하고 마이그레이션을 적용해야 합니다. DB 시험용 `NETWATCHER_TEST_DB_*`도 함께 설정합니다. 검사에서는 로컬 `.env`가 적용되지 않습니다.

설정·인증·승인·방화벽 명령·마이그레이션·회귀 시험을 검사합니다. 실제 네트워크 처리량, OS 차단 효과와 장시간 안정성은 별도 검증이 필요합니다.

## 변경 작성

- 탐지는 기존 엔진 인터페이스와 설정 검증을 사용합니다.
- 대시보드는 기존 ES 모듈과 한국어·영어 번역을 사용합니다.
- 저장·승인·외부 전달은 실패와 미확정 상태를 구분합니다.
- 사용법이 달라지면 해당 가이드와 릴리스 노트를 함께 수정합니다.
- 비밀번호, 토큰, 원본 패킷과 특정 운영 환경의 자료는 커밋하지 않습니다.

PR에는 해결하는 문제, 변경 후 동작, 검증 결과와 알려진 제한을 적어주세요. 자세한 검토 기준은 [기여 기준](GOVERNANCE.md), 합성 성능 측정은 [성능 시험 안내](../tests/performance/README.md)를 참고하세요.
