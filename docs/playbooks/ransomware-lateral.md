# Ransomware Lateral Movement 대응 플레이북

ATT&CK TTP: T1486 (Data Encrypted for Impact), T1021 (Remote Services)
트리거: `ransomware_lateral` 엔진 CRITICAL 알림

---

## 1단계 — 즉시 격리

목표: 랜섬웨어 확산 경로를 차단하고 피해 범위를 최소화한다.

**조치 항목:**
- 의심 호스트를 네트워크에서 즉시 분리
  - 물리적 분리: 케이블 제거 또는 스위치 포트 비활성화
  - 논리적 분리: 격리 VLAN으로 이동
  ```
  # NetWatcher 자동 차단 (response 설정이 활성화된 경우)
  # 또는 수동 등록:
  POST /api/blocklist
  {"entry_type": "ip", "value": "<source_ip>", "notes": "Ransomware 격리"}
  ```
- 공유 폴더 및 NAS를 읽기 전용으로 전환
  ```bash
  # Samba 예시
  net usershare list
  # 해당 공유 임시 중지
  ```
- SMB(445), RDP(3389) 포트를 방화벽에서 즉시 차단

**확인:**
- 격리 이후 `ransomware_lateral` 엔진 신규 알림이 감소하는지 확인
- 인접 호스트에서 새 알림 발생 여부 모니터링 (확산 여부)

---

## 2단계 — 백업 무결성 확인 및 피해 범위 파악

목표: 복구 가능 여부를 판단하고 감염 범위를 확정한다.

**조치 항목:**
- 백업 시스템 접근 가능 여부 확인
  - 마지막 정상 백업 일시 확인
  - 백업 파일이 암호화/변조되지 않았는지 해시 검증
- 감염 파일 확장자 스캔 (알려진 랜섬웨어 확장자: `.locked`, `.encrypted`, `.WNCRY` 등)
  ```bash
  find /mnt/shared -name "*.encrypted" -o -name "*.locked" 2>/dev/null | head -50
  ```
- 관련 이벤트 이력 조회 (최초 발생 시점 파악)
  ```
  GET /api/events?engine=ransomware_lateral&limit=200
  GET /api/incidents
  ```
- 감염 경로 추적: `lateral_movement` 엔진 이벤트와 시계열 연관 분석
- 인시던트 번호 발급, CISO 에스컬레이션, 법적 보존 여부 판단

---

## 3단계 — 복구 및 재발 방지

목표: 피해 시스템을 정상화하고 동일 공격 경로를 차단한다.

**복구 절차:**
- 감염 호스트를 클린 이미지 또는 최신 정상 백업에서 복원
  - 복원 전 포렌식 이미지 보존 필수
- 복원된 시스템의 패치 수준 확인 후 재연결
  ```
  # 재연결 전 체크리스트
  - OS 최신 보안 패치 적용 여부
  - EDR/AV 에이전트 활성화 여부
  - 계정 비밀번호 초기화 여부
  ```
- 관리자 계정 및 서비스 계정 비밀번호 전면 교체

**재발 방지:**
- SMB/RDP 접근을 최소 권한 원칙으로 재설계
- NetWatcher `lateral_movement` 엔진 임계값 조정 (필요 시 낮춤)
- EDR 정책 강화: 횡적 이동 관련 행위 차단 규칙 추가
- 백업 정책 검토: 오프라인(에어갭) 백업 주기 단축

**사후 처리:**
- T1486, T1021 기준 TTP 문서화
- 인시던트 보고서 작성 (최초 침입 벡터, 확산 경로, 복구 소요 시간)
- 동일 패턴에 대한 NetWatcher 시그니처 업데이트 검토
