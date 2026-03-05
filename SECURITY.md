# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | Yes |

## Reporting a Vulnerability

보안 취약점을 발견했다면 공개 이슈가 아닌 아래 채널로 직접 보고한다.

- 보고 방법: 프로젝트 관리자에게 비공개 채널(이메일 또는 GitHub Security Advisory)로 연락
- 응답 기한: 영업일 기준 3일 이내 확인, 7일 이내 초기 대응
- 공개 타임라인: 패치 배포 후 30일 경과 시 공개 허용

보고 시 포함할 내용:
- 취약점 유형 및 영향 범위
- 재현 절차 (단계별)
- 개념 증명(PoC) 코드 또는 스크린샷
- 예상 심각도 (CVSS 기준)

## Security Frameworks & References

이 프로젝트의 탐지 로직과 대응 절차는 다음 프레임워크를 기준으로 설계되었다.

### MITRE ATT&CK
- 사이버 공격 전술·기술·절차(TTP) 분류 체계
- 각 탐지 엔진은 관련 ATT&CK 기술 ID를 `mitre_attack_ids` 속성으로 매핑함
- https://attack.mitre.org/

### MITRE D3FEND
- 방어 대응 기술 분류 체계 (ATT&CK의 방어 측면 대응)
- https://d3fend.mitre.org/

### CISA
- 미국 사이버보안 및 인프라 보안국 공식 권고문
- https://www.cisa.gov/news-events/cybersecurity-advisories

### NIST SP 800-61
- 컴퓨터 보안 인시던트 처리 가이드
- https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final

### CIS Controls v8
- 우선순위 기반 사이버보안 통제 항목
- https://www.cisecurity.org/controls/v8

## Threat Detection Scope

NetWatcher가 현재 탐지하는 위협 유형 및 매핑된 ATT&CK TTP:

| 탐지 엔진 | 위협 유형 | ATT&CK TTP |
|-----------|-----------|------------|
| arp_spoof | ARP Cache Poisoning (MITM) | T1557.002 |
| dhcp_spoof | DHCP Spoofing | T1557.003 |
| mac_spoof | MAC Address Masquerading | T1036.005 |
| icmp_anomaly | Ping Sweep, ICMP Flood | T1018 |
| protocol_anomaly | Protocol Abuse, TTL Manipulation | T1071 |
| dns_anomaly | DNS Tunneling, DGA | T1071.004 |
| http_suspicious | Malicious HTTP Patterns, C2 Beaconing | T1071.001, T1190 |
| data_exfil | Large Outbound Transfers | T1048, T1030 |
| lateral_movement | Internal Port Scanning, Sensitive Port Access | T1021 |
| ransomware_lateral | SMB/RDP Brute Force, Lateral Spread | T1486, T1021 |
| threat_intel | Known Malicious IP/Domain Communication | T1590 |
| port_scan | Network Service Discovery | T1046 |
| traffic_anomaly | Volume Anomaly, New Device Detection | T1018, T1041 |
| tls_fingerprint | Suspicious TLS Fingerprints (JA3/JA4) | T1573 |
| behavior_profile | Host Behavior Deviation | T1041 |
| data_exfil | Data Exfiltration | T1048, T1030 |

## Incident Response Playbooks

대표적인 위협 시나리오별 대응 절차는 아래 플레이북을 참고한다.

- [ARP Spoofing 대응](docs/playbooks/arp-spoof.md)
- [Ransomware Lateral Movement 대응](docs/playbooks/ransomware-lateral.md)
- [Port Scan 대응](docs/playbooks/port-scan.md)

## Secure Deployment Checklist

프로덕션 배포 전 아래 항목을 확인한다.

- [ ] `config/default.yaml`에 DB 자격증명 직접 기입 금지 — 환경변수 사용
- [ ] Web UI 인증 활성화 (`web.auth.enabled: true`)
- [ ] TLS 설정 또는 리버스 프록시를 통한 HTTPS 강제
- [ ] 불필요한 엔진 비활성화 (SPAN 없는 환경에서 `requires_span: true` 엔진 주의)
- [ ] 로그 디렉토리 권한 제한 (root 또는 netwatcher 전용 사용자)
- [ ] Webhook URL(Slack/Telegram/Discord)은 `.env` 파일 또는 시크릿 관리자에 저장
