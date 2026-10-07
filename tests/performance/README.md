# 성능 계측과 격리 재현

`scripts/perf_replay.py`는 실제 PacketSniffer 입력 브릿지, PacketProcessor,
EngineRegistry, TickService, AlertDispatcher, EventRepository, PCAPWriter를
합성 패킷으로 실행한다. 운영 NetWatcher를 시작하지 않고 별도 PostgreSQL의
무작위 스키마를 만든 뒤 종료 시 제거한다. 실제 NIC 캡처·방화벽 변경·외부
웹훅·DNS 요청을 실행하지 않는다.

## 준비와 실행

전용 PostgreSQL 데이터베이스를 준비한다. 이름은 `netwatcher_perf_`로
시작해야 하며 localhost 또는 `/tmp/` 아래 Unix socket만 허용한다.
운영 DB 접속값이나 저장소 `.env`는 읽지 않는다. 비밀번호가 필요하면
`NETWATCHER_PERF_DB_PASSWORD` 환경변수로 주입한다.

```bash
NETWATCHER_SKIP_DOTENV=1 .venv-new/bin/python scripts/perf_replay.py \
  --scenario normal --duration-seconds 30 --pps 100 --pcap \
  --db-name netwatcher_perf_local --db-user netwatcher \
  --output-dir /tmp/panopticon-normal-run-1
```

출력 디렉터리는 저장소 밖의 새 경로여야 한다. 기존 경로는 덮어쓰지 않는다.
`result.json`과 선택적 `pcaps/`를 남긴다. PCAP 보존 상한은 이 도구에서
8MiB로 제한하며 운영 설정이나 운영 PCAP 경로를 바꾸지 않는다.

| 시나리오 | 입력 | 해석 |
|---|---|---|
| normal | DNS·NAS/DB/VM 모양의 합성 TCP | 정상 업무 레이블의 정답 세트는 아님 |
| mixed | 위 입력과 SYN 스캔 혼합 | 실제 탐지 엔진 경로 측정 |
| alert-storm | 패킷 입력과 같은 키 경보 직접 주입 | 키별 제한·큐·DB 경로 측정 |
| unique-key | 패킷 입력과 서로 다른 title 경보 주입 | 고유 키 폭증의 저장 부하 측정 |

`--alerts-per-second`는 주입 시나리오의 경보 목표 속도다. 직접 주입 경보는
탐지 엔진의 악성 판정 결과가 아니다. `--pcap` 유무만 바꾸고 동일 시드·pps·기간을
사용하면 증거 I/O의 영향을 비교할 수 있다. 기본 단계는 workers=1이며,
workers 2/4, 정상·공격 정답 묶음, 업무 시각표, stats flush와 외부 채널 비교는
후속 검증 대상이다.

## 결과 해석

- requested/planned 입력과 emitted 입력을 함께 기록한다. 생성기 미전송을
  애플리케이션 drop에 더하지 않는다.
- 입력 큐 손실의 분모는 큐 진입을 시도한 전체 입력이다. 5개 중 3개 거절은
  60%이며, 진입 성공 2개를 분모로 한 150%가 아니다.
- 큐 `wire_bytes`는 저장된 raw 패킷 바이트 수다. Python 객체 메모리는
  포함하지 않으며 별도 process peak RSS로 확인한다.
- snapshot의 kernel 카운터가 0이어도 커널 손실 0을 검증한 것이 아니다.
  재현 도구의 `measured_kernel_drop`은 null이고 실제 NIC·링크는 미측정이다.
- Prometheus histogram은 누적 bucket·count·sum이다. quantile은 bucket으로
  추정할 수 있지만 정확한 개별 지연 표본이나 실제 p99 값으로 보고하지 않는다.
- 이벤트 DB 커밋, PCAP 파일 작업, 큐 대기, 이벤트 루프 지연을 함께 비교한다.
  이벤트 수 감소를 오탐 감소로 해석하지 않는다.
- CPU 시간에는 준비·drain이 포함되며 peak RSS에도 준비 단계가 포함된다.
  측정 프로세스 자체에 대한 값이고 PostgreSQL RSS/CPU는 합산하지 않는다.
- 코드 revision, dirty 여부, Python·플랫폼, 입력/설정 해시를 남긴다.
  동일 해시는 입력 패킷 묶음을 가리키며 OS 스케줄·수신 timestamp까지 같다는
  뜻은 아니다.

## 검증 범위

```bash
NETWATCHER_SKIP_DOTENV=1 .venv-new/bin/python -m pytest \
  tests/test_observability tests/test_alerts/test_dispatcher_durability.py \
  tests/performance -q -p no:cacheprovider
```

단기 재현 통과는 도구의 연결과 영속화 확인이다. 계획의 정상 30분·폭풍 10분
기준 실측, 24시간 부하, HDD·저사양 장비의 목표 달성을 대신하지 않는다.
