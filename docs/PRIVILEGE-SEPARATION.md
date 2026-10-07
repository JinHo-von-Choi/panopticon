# 웹·센서·강제 실행 권한 분리 설계

현재 배포 엔트리포인트는 웹과 캡처를 같은 프로세스 권한으로 실행합니다.
`netwatcher.service`의 root 사용을 최소 권한 분리가 끝난 것으로 보고하지 않습니다.
새 replay worker는 순수 연산만 분리했으며 센서의 권한 분리를 대신하지 않습니다.
자동 차단은 기본 비활성이며 새 실행 경로도 현장 검증 전 shadow로 제공합니다.

## 목표 프로세스와 계약

- 웹/API: 전용 사용자, Linux capability 없음, PostgreSQL 조회·승인 API와 원자적 설정
  저장만 수행. raw socket·방화벽 명령·임의 프로세스 실행 권한을 받지 않습니다.
- 센서: 별도 사용자와 `CAP_NET_RAW`만 기본 후보로 부여. `CAP_NET_ADMIN`이 필요한
  promiscuous 설정은 배포 시 인터페이스별로 검토합니다. 외부 egress는 피드/알림
  프로세스와 분리하며 캡처·엔진 상태의 단일 소유자를 둡니다.
- 강제 실행 helper: 검증된 관측/관리 경로에서만 `CAP_NET_ADMIN`, root 전체 권한은
  기본 후보가 아닙니다. 웹에서 임의 shell·nft 문장·경로를 넘기지 않습니다.

센서→웹 데이터 경계는 로컬 Unix domain socket, 소유 계정과 0660, `SO_PEERCRED`
검사로 한정합니다. 메시지는 길이 접두어+UTF-8 JSON, 최대 64KiB, 버전·sensor ID·
단조 증가 sequence·UTC 관측 시각·카운터 분모·손실 구간·소유 세대·이벤트 UUID를
필수로 갖습니다. payload는 명시적으로 선택한 근거만 전송하며 무한 PCAP 스트림은
없습니다. 생산자는 유한 큐와 byte 상한을 가지며 웹 단절 시 대기 상한 후 손실을
기록합니다. 재연결은 이전 sequence와 누락 구간을 전달하고 UUID로 중복을 제거합니다.
프로토콜 버전 불일치는 unknown/비교 불가이며 정상으로 보정하지 않습니다.

웹→helper 계약은 `propose`, `apply`, `expire`, `status` 네 종류의 고정 메시지입니다.
apply에는 승인 ID·행위자·목표 IP/MAC·mapping version·confirmation timestamp·정확한
범위·TTL·idempotency key·승인 시각·설정/빌드 버전이 필요합니다. 서버에서 서명된
승인과 현재 소유 관계를 재검증하며 문자열 명령은 없습니다. 허용 nft table/chain은
helper 내부에서 고정합니다. 같은 key의 재요청은 상태 조회로 응답하며, 응답 유실은
unknown으로 남깁니다. timeout=복구 완료로 처리하지 않습니다.

## 구현·배포 진입 조건

이 문서는 다음 단계 계약이며 socket transport와 계정 분리를 배포한 상태가 아닙니다.
그 구현에는 단일 DB/설정 작성자, 센서 restart 상태 복원, 연결 단절과 역압, peer UID,
메시지 크기·버전·순서·중복·invalid JSON, 웹에서 raw socket/nft 실행 거부 시험이
필요합니다. 기존 서비스는 이 검증 전 자동으로 바꾸지 않습니다.

nft backend 활성화에는 실제 트래픽 경로를 제어하는 gateway/host 위치, 관리 경로
복구, reboot 후 TTL 재조정, 실제 적용·해제·반환 상태 및 다른 업무 연결 보존을
현장에서 확인해야 합니다. SPAN 센서의 INPUT 차단은 다른 호스트 사이의 트래픽
차단 근거가 아닙니다. 미확인 환경에는 shadow/제안만 제공하며 성공 문구를 표시하지 않습니다.
