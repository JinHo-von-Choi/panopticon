# ARP Spoofing 대응 플레이북

ATT&CK TTP: T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)
트리거: `arp_spoof` 엔진 CRITICAL 알림

---

## 1단계 — 즉시 격리

목표: 공격자가 추가 트래픽을 가로채지 못하도록 즉시 차단한다.

**조치 항목:**
- 의심 MAC 주소를 스위치 포트 레벨에서 비활성화
  ```
  # Cisco IOS 예시
  interface GigabitEthernet0/X
    shutdown
  ```
- 해당 VLAN을 격리 VLAN으로 이동하거나 ACL 적용
- NetWatcher 커스텀 차단 목록에 의심 IP/MAC 등록
  ```
  POST /api/blocklist
  {"entry_type": "ip", "value": "<source_ip>", "notes": "ARP Spoof 격리"}
  ```

**확인:**
- 해당 포트에서 트래픽이 차단되었는지 스위치 로그로 확인
- NetWatcher 대시보드에서 동일 source_ip 알림 추가 발생 여부 모니터링

---

## 2단계 — 증거 수집

목표: 포렌식 분석에 필요한 증거를 수집하고 인시던트 번호를 발급한다.

**조치 항목:**
- NetWatcher PCAP 파일 수집 (`data/pcap/` 디렉토리)
- 관련 이벤트 이력 조회
  ```
  GET /api/events?engine=arp_spoof&source_ip=<IP>&limit=100
  ```
- 스위치 MAC 주소 테이블 덤프
  ```
  show mac address-table | include <suspect_mac>
  ```
- 피해 가능성 있는 호스트 목록 조회 (동일 서브넷)
  ```
  GET /api/devices
  ```
- 인시던트 번호 발급 및 CISO/보안팀 에스컬레이션 (CRITICAL 이상 필수)

---

## 3단계 — 원인 분석 및 복구

목표: 공격 여부와 영향 범위를 확정하고 정상 상태로 복구한다.

**분석 항목:**
- IP 충돌 여부 확인 (실수로 동일 IP를 두 기기에 설정한 경우와 구분)
- 피해 기기의 ARP 캐시 확인
  ```bash
  arp -a  # 또는 ip neigh show
  ```
- 패킷 캡처 분석: 동일 IP에 대한 복수 MAC의 ARP Reply 패턴 확인
- 가로채기 된 세션 식별 (HTTP, FTP 등 평문 프로토콜 우선)

**복구 절차:**
- 피해 기기의 ARP 캐시 초기화
  ```bash
  ip neigh flush all  # Linux
  arp -d <ip>         # Windows/Mac
  ```
- 정상 기기 재연결 허용 전 MAC 주소 확인
- Static ARP 엔트리 설정 (반복 공격 방지)
- Dynamic ARP Inspection(DAI) 스위치 설정 검토

**사후 처리:**
- T1557.002 기준 TTP 문서화
- 인시던트 보고서 작성 (발생 시각, 영향 기기, 대응 조치, 재발 방지 계획)
- NetWatcher 화이트리스트 및 차단 목록 정리
