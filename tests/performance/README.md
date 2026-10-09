# 합성 성능 시험

EVE 수집과 패킷 탐지의 처리 성능을 로컬에서 측정하는 도구입니다. 실제 네트워크 장비나 운영 DB는 쓰지 않습니다.

| 도구 | 측정 대상 |
| --- | --- |
| `scripts/perf_eve.py` | 합성 Suricata 경보를 파일에 쓰고 DB 저장까지 걸리는 전체 과정 |
| `scripts/perf_replay.py` | 합성 패킷으로 탐지 엔진, 경보 저장, 증거 수집 부하 |

## 공통 조건

- 로컬 PostgreSQL에 이름이 `netwatcher_perf_`로 시작하는 DB를 만듭니다. 임시 스키마를 만들었다가 끝나면 지웁니다.
- DB 비밀번호는 `NETWATCHER_PERF_DB_PASSWORD`로 넘깁니다.
- 출력 경로는 저장소 밖의 새 디렉터리를 지정합니다. 이미 있으면 덮어쓰지 않습니다.
- 현재 소스 트리의 스키마 정의를 씁니다. 운영 마이그레이션 호환성은 따로 확인합니다.

## EVE 수집

```bash
NETWATCHER_SKIP_DOTENV=1 .venv/bin/python scripts/perf_eve.py \
  --duration-seconds 30 --events-per-second 1000 \
  --db-name netwatcher_perf_local --db-user netwatcher \
  --output-dir /tmp/panopticon-eve-perf-run
```

`result.json`에서 확인할 값:

| 키 | 의미 |
| --- | --- |
| `emitted_records` | 생성한 입력 수 (요청 속도와 다를 수 있음) |
| `stored_records`, `stored_events` | DB에 저장된 원기록 수, 사건 수 |
| `all_emitted_records_stored` | 생성분을 모두 저장했는지 |
| `source_duration_completed` | 요청한 생성 시간을 채웠는지 |

- 생성이 끝난 뒤 남은 입력을 최대 30초 더 처리합니다. 수집을 멈춘 다음 한 번의 DB 조회로 기록 수와 사건 수를 셉니다.
- 지연은 경보 생성 시각부터 DB 저장 완료까지입니다. p95는 10% 폭 히스토그램의 상한값입니다. 시스템 시계가 틀리면 지연 값을 믿을 수 없습니다.
- CPU 시간에는 생성기와 측정 코드가 포함되고, HTTP 서버·Suricata·DB의 자원은 빠집니다.
- 입력 파일과 보존 한도 기본값은 256MiB·250,000건입니다. 긴 시험은 `--max-source-bytes`, `--max-retained-bytes`, `--max-retained-records`로 늘립니다.

통과 조건은 네 가지가 모두 참일 때입니다: 요청한 생성 시간을 채움, 입력 용량 상한에 닿지 않음, 생성분을 모두 저장함, 수집 상태가 정상. 생성이 오류로 일찍 멈추면 저장을 다 했어도 실패입니다. 저장하지 못한 입력 수를 NIC 패킷 손실률로 바꿔 해석하지 않습니다.

## 패킷 탐지

```bash
NETWATCHER_SKIP_DOTENV=1 .venv/bin/python scripts/perf_replay.py \
  --scenario normal --duration-seconds 30 --pps 100 --pcap \
  --db-name netwatcher_perf_local --db-user netwatcher \
  --output-dir /tmp/panopticon-perf-run
```

| 시나리오 | 측정 대상 |
| --- | --- |
| `normal` | 합성 DNS·TCP 입력의 기본 처리 |
| `mixed` | 기본 입력과 SYN 스캔 탐지 경로 |
| `alert-storm` | 같은 조건 경보의 집계와 저장 |
| `unique-key` | 다른 조건 경보가 늘어날 때의 저장 부하 |

`--pcap`은 증거 파일도 씁니다. `--alerts-per-second`는 경보를 직접 넣는 시나리오의 목표 속도입니다.

`result.json`에서 요청량과 실제 생성량, 처리·저장량, 대기 시간, 누락 수, CPU·메모리를 함께 봅니다.

- 생성기가 못 낸 입력과 앱이 놓친 입력을 구분합니다.
- 대기열 바이트 집계에는 Python 객체 오버헤드가 들어가지 않습니다.
- 단일 워커로만 돕니다. NIC 한계, 외부 알림, 통계 저장, 차단 성능은 다루지 않습니다.

## 비교할 때

- 시드, 입력량, 기간을 같게 두고 변수 하나만 바꿉니다.
- 탐지 사건 수가 줄었다고 오탐률이 낮아졌다고 보지 않습니다. 정상·공격 레이블이 확인된 샘플이 따로 필요합니다.
- 물리 장비 처리량, 디스크 I/O 지연, 장시간 안정성은 대상 환경에서 따로 측정합니다.
