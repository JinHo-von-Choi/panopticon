# Port Scan 대응 플레이북

ATT&CK TTP: T1046 (Network Service Discovery)
트리거: `port_scan` 엔진 WARNING/CRITICAL 알림

---

## 1단계 — 출처 확인

목표: 스캔 출처가 내부인지 외부인지, 인가된 활동인지 판단한다.

**조치 항목:**
- source_ip 위치 파악
  ```
  GET /api/devices?ip=<source_ip>
  ```
  - 내부 IP이면서 인벤토리에 없는 경우: 미인가 내부 스캐너 의심
  - 외부 IP(공인 IP)인 경우: 외부 공격자 또는 외부 스캐너
- 동일 IP의 과거 이벤트 조회
  ```
  GET /api/events?source_ip=<source_ip>&limit=50
  ```
- 스캔 목적지 포트 패턴 분석: 특정 서비스(22, 80, 443, 3389) 집중 vs. 전체 포트 랜덤

---

## 2단계 — 허용 여부 판단

목표: 인가된 스캔인지 아닌지를 결정하고 적절한 조치를 선택한다.

**인가된 스캔인 경우:**
- 취약점 스캐너(Nessus, Qualys, OpenVAS 등) 또는 보안 감사 출처로 확인되면
- 해당 IP를 화이트리스트에 등록하여 향후 알림 억제
  ```
  POST /api/whitelist
  {"type": "ip", "value": "<scanner_ip>", "note": "Nessus 취약점 스캐너"}
  ```
- 스캔 일정 및 담당자 정보를 인시던트 로그에 기록 후 종료

**미인가 스캔인 경우 — 3단계로 진행:**
- 승인된 스캐너 목록에 없는 내부 IP
- 외부에서 유입된 스캔
- 스캔 빈도가 비정상적으로 높은 경우 (threshold 초과)

---

## 3단계 — 차단 및 모니터링

목표: 미인가 스캔을 차단하고 공격으로 이어지는지 감시한다.

**즉시 차단:**
- 방화벽/ACL에서 source_ip 차단
  ```bash
  # iptables 예시
  iptables -I INPUT -s <source_ip> -j DROP
  iptables -I FORWARD -s <source_ip> -j DROP
  ```
- NetWatcher 커스텀 차단 목록 등록
  ```
  POST /api/blocklist
  {"entry_type": "ip", "value": "<source_ip>", "notes": "Port Scan 차단"}
  ```

**모니터링 강화 (72시간):**
- 동일 서브넷에서 유사 패턴 발생 여부 감시
- `port_scan` 엔진 설정에서 임계값 일시적으로 낮춤 (YAML 또는 API를 통해)
  ```
  PATCH /api/engines/port_scan
  {"threshold": 5, "window_seconds": 30}
  ```
- 스캔 대상 포트가 실제로 열려 있는지 확인 및 불필요한 서비스 비활성화

**사후 처리:**
- T1046 기준 TTP 문서화
- 외부 스캔인 경우: ISP 신고 또는 IDS/IPS 규칙 추가 검토
- 내부 미인가 스캔인 경우: 해당 사용자/시스템 조사 및 내부 정책 위반 처리
- 인시던트 보고서 작성 (스캔 범위, 대상 포트, 차단 조치)
