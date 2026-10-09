# 자동 업데이트

관리형 설치 환경에서는 최초 등록 시점과 매일 호스트 시간대 기준 새벽 4시에 GitHub의 최신 정식 릴리스를 확인합니다. 더 높은 버전이 발견되면 서명과 체크섬을 검증한 뒤 자동으로 적용하며, 시험판이나 이전 버전은 설치 대상에서 제외합니다.

컨테이너 내부에는 업데이트 권한이 없습니다. 호스트에 상주하는 별도 systemd 실행기가 콘솔과 센서를 함께 갱신하도록 설계되어 있으며, 일반 실행 환경이나 개발용 체크아웃은 따로 등록하지 않는 한 변경되지 않습니다.

## 등록하기

Linux와 systemd, 그리고 `gh attestation verify`를 지원하는 GitHub CLI가 필요합니다. Compose 구성에는 Docker Compose를 준비하고, 호스트 직접 실행 구성이라면 Python 3.12 이상과 함께 DB 서버 버전 이상의 PostgreSQL 클라이언트 도구(`pg_dump`, `pg_restore`, `createdb`, `dropdb`)를 갖추어야 합니다.

코드 디렉터리는 반드시 root 소유로 설정해 다른 계정의 쓰기 접근을 차단합니다. 설정·자격증명·로그·증거 자료는 해당 디렉터리 외부에 분리 보관하며, 자동 복원 처리를 위해 Panopticon 전용 DB와 백업·복원 권한을 가진 관리 계정이 필수적이므로 다른 서비스와 DB를 공유하는 환경에는 등록하지 마십시오.

아래는 코드가 `/opt/panopticon`에 위치하고 기존 Compose 환경 파일이 `/etc/panopticon/installation.env`에 있는 EVE 설치 예시입니다. 기존 볼륨을 그대로 이어 쓰려면 환경 파일의 `COMPOSE_PROJECT_NAME`이 현재 설치의 프로젝트 이름과 반드시 일치해야 하며, 환경 파일 내부의 설정 경로 역시 기존 외부 설정을 가리키고 있어야 합니다.

```bash
sudo python3 /opt/panopticon/scripts/install_auto_update.py \
  --mode compose-eve \
  --source /opt/panopticon \
  --env-file /etc/panopticon/installation.env
```

Native Compose는 `--mode compose-native`로 등록하면서 `--database-env`에 기존 `bootstrap.env` 경로를 넘깁니다. 외부 PostgreSQL을 연동한 Compose 환경이라면 `--external-database` 플래그를 추가합니다.

EVE systemd 구성에서는 기존 서비스 이름과 설정 파일 경로를 지정합니다.

```bash
sudo python3 /opt/panopticon/scripts/install_auto_update.py \
  --mode systemd-eve \
  --source /opt/panopticon \
  --env-file /etc/panopticon/panopticon.env \
  --config /etc/panopticon/config.yaml \
  --services panopticon-eve.service
```

Native systemd 환경은 `--mode systemd-native`를 지정하고, `--env-file`에는 `console.env`, `--database-env`에는 `bootstrap.env`, `--migration-env`에는 `migrate.env`, `--grants-env`에는 `grants.env`를 전달하며 `--services`에 콘솔과 센서 서비스 이름을 모두 나열합니다. 콘솔 설정 파일은 `--config`로 지정하고, 기본 웹 포트를 바꾼 경우라면 `--port`도 그에 맞춰 지정합니다.

등록이 끝나면 기존 코드 디렉터리가 버전별 보관 디렉터리로 이동하고 원본 경로에는 심볼릭 링크가 생성됩니다. 코드 경로와 보관 경로는 동일 파일시스템에 위치해야 하며, 기존 설정과 데이터는 이동하거나 초기화하지 않습니다. 타이머는 등록 즉시 활성화되어 첫 확인 작업을 실행하고, 정각 4시에 호스트가 꺼져 있었다면 다음 부팅 시점에 즉시 확인에 들어갑니다.

## 끄거나 다시 켜기

`/etc/panopticon-update/update.env` 파일에 아래 환경변수를 지정합니다.

```dotenv
PANOPTICON_AUTO_UPDATE=false
```

이 값을 반영하면 다음 실행 주기부터 GitHub 확인, 릴리스 다운로드, 신규 버전 적용 과정 전체를 건너뜁니다. 기능을 재개할 때는 값을 `true`로 되돌리면 되며, 이전에 진행 중이던 작업의 복구 기록이 남아 있다면 서비스 복구 작업을 먼저 완료합니다.

## 적용과 실패 복구

서명 검증과 신규 실행 환경 준비 작업은 운영 중인 기존 서비스를 중단하지 않고 백그라운드에서 진행합니다. 실제 적용 단계에 진입하면 콘솔과 센서를 잠시 멈춘 뒤 DB 백업과 마이그레이션을 차례로 실행하며, 직후 새 코드로 서비스를 기동하여 버전과 프로세스 정상 여부를 점검합니다. 이 업데이트 작업 중에는 경보 조사가 일시 중단됩니다.

적용에 실패하면 이전 코드와 DB 상태로 즉시 롤백합니다. 전원 차단 등으로 작업이 비정상 종료되더라도 다음 실행 때 복구 기록을 참조해 직전 버전으로 온전히 되돌립니다. 복원 절차마저 실패할 경우에는 서비스를 정지 상태로 유지하면서 상세 기록과 백업본을 보존합니다. 생성된 백업은 `/var/lib/panopticon-updater/backups` 디렉터리에 계속 누적되므로 디스크 잔여 용량을 주기적으로 확인해야 합니다.

```bash
systemctl list-timers panopticon-update.timer
sudo journalctl -u panopticon-update.service --no-pager -n 30
sudo cat /var/lib/panopticon-updater/status.json
```

지금 바로 업데이트 여부를 확인하려면 `sudo systemctl start panopticon-update.service`를 입력합니다. 업데이트 스케줄러 자체를 완전히 비활성화하려면 `sudo systemctl disable --now panopticon-update.timer`를 실행합니다.