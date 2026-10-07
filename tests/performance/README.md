# 합성 성능 시험

`scripts/perf_replay.py`는 합성 패킷으로 탐지·경보 저장·증거 수집을 실행하는 개발용 도구입니다. 별도 PostgreSQL DB에 임시 스키마를 만들고 종료 시 제거합니다. 운영 DB와 실제 네트워크를 사용하지 않습니다.

## 실행

DB 이름은 `netwatcher_perf_`로 시작해야 하고 로컬 DB만 사용할 수 있습니다. 비밀번호는 `NETWATCHER_PERF_DB_PASSWORD` 환경변수에 설정합니다. 출력은 저장소 밖의 새 디렉터리를 지정합니다.

```bash
NETWATCHER_SKIP_DOTENV=1 .venv/bin/python scripts/perf_replay.py \
  --scenario normal --duration-seconds 30 --pps 100 --pcap \
  --db-name netwatcher_perf_local --db-user netwatcher \
  --output-dir /tmp/panopticon-perf-run
```

| 시나리오 | 측정 대상 |
| --- | --- |
| `normal` | 합성 DNS·TCP 입력의 기본 처리 |
| `mixed` | 기본 입력과 SYN 스캔의 탐지 경로 |
| `alert-storm` | 같은 조건의 경보 집계와 저장 |
| `unique-key` | 다른 조건의 경보가 증가할 때의 저장 부하 |

`--pcap`을 켜면 증거 파일도 기록합니다. `--alerts-per-second`는 경보 직접 주입 시나리오의 목표 속도입니다. 기존 출력 디렉터리는 덮어쓰지 않습니다.

## 결과 해석

`result.json`에서 요청 입력량과 실제 생성량, 처리·저장량, 큐 대기와 누락, CPU·메모리를 함께 봅니다. 생성기가 보내지 못한 입력은 앱의 패킷 누락과 구분합니다. 큐의 패킷 바이트에는 Python 객체 메모리가 포함되지 않습니다.

같은 시드·입력량·기간에서 한 조건만 바꿔 비교합니다. 사건 수가 줄었다는 이유로 오탐이 줄었다고 계산하지 않습니다. 정상·공격 분류가 확인된 별도 샘플이 필요합니다.

이 도구는 단일 워커를 사용하며 실제 NIC, 외부 알림, 통계 저장과 네트워크 차단을 시험하지 않습니다. CPU·메모리에는 준비와 종료 작업이 포함되고 DB 프로세스의 자원은 별도입니다. 실제 장비의 처리량·디스크 지연·장시간 안정성은 해당 환경에서 따로 확인하세요.
