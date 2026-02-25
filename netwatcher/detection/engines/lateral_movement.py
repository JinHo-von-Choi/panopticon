"""횡이동 탐지: 내부 호스트의 측면 이동 포트 스캔."""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Any

from scapy.all import IP, TCP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.utils import get_ip_addrs, is_internal

logger = logging.getLogger("netwatcher.detection.engines.lateral_movement")

# 기본 횡이동 포트
_DEFAULT_LATERAL_PORTS = [22, 445, 3389, 135, 5985, 5986, 23, 3306, 5432, 1433, 6379, 27017]


class LateralMovementEngine(DetectionEngine):
    """내부 횡이동 패턴을 탐지한다.

    - 단일 내부 호스트가 다수의 내부 호스트에서 측면 이동 포트에 접근
    - 연결 체인 탐지 (A->B->C->D)
    """

    name = "lateral_movement"
    description = "내부 네트워크 횡이동을 탐지합니다. 단일 호스트가 다수의 내부 서비스에 접근하는 패턴으로 침투 확산을 식별합니다."
    config_schema = {
        "lateral_ports": {
            "type": list, "default": [22, 445, 3389, 135, 5985, 5986, 23, 3306, 5432, 1433, 6379, 27017],
            "label": "측면 이동 감시 포트",
            "description": "측면 이동에 사용되는 포트 목록 (쉼표 구분). "
                           "SSH(22), SMB(445), RDP(3389), WinRM(5985), DB 포트 등. "
                           "내부 네트워크에서 이 포트들의 비정상 접근 패턴을 감시.",
        },
        "unique_host_threshold": {
            "type": int, "default": 5, "min": 2, "max": 50,
            "label": "고유 호스트 임계값",
            "description": "단일 출발지가 윈도우 내 접근한 고유 내부 호스트 수가 이 값을 초과하면 알림. "
                           "측면 이동 시 공격자는 여러 내부 호스트를 순차적으로 탐색함.",
        },
        "window_seconds": {
            "type": int, "default": 300, "min": 60, "max": 3600,
            "label": "탐지 윈도우(초)",
            "description": "측면 이동 활동을 집계하는 시간 윈도우. 기본값 5분.",
        },
        "chain_depth_threshold": {
            "type": int, "default": 3, "min": 2, "max": 10,
            "label": "체인 깊이 임계값",
            "description": "A->B->C->D 형태의 접근 체인 깊이가 이 값을 초과하면 알림. "
                           "측면 이동의 전형적인 패턴(피벗 체인) 탐지.",
        },
        "max_tracked_connections": {
            "type": int, "default": 10000, "min": 100, "max": 1000000,
            "label": "최대 추적 연결 수",
            "description": "메모리에 유지하는 연결 추적 테이블 크기.",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """횡이동 탐지 엔진을 초기화한다. 감시 포트, 임계값 등을 설정한다."""
        super().__init__(config)
        self._lateral_ports = set(config.get("lateral_ports", _DEFAULT_LATERAL_PORTS))
        self._unique_host_threshold = config.get("unique_host_threshold", 5)
        self._window = config.get("window_seconds", 300)
        self._chain_depth_threshold = config.get("chain_depth_threshold", 3)

        # src_ip -> (timestamp, dst_ip, dst_port) deque
        self._lateral_connections: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        # 체인 탐지용: dst_ip -> 접속한 src_ip 집합
        self._connection_graph: dict[str, set[str]] = defaultdict(set)
        self._alerted: dict[str, float] = {}
        self._chain_alerted: set[str] = set()

    def analyze(self, packet: Packet) -> Alert | None:
        """내부 호스트 간 횡이동 포트 SYN 패킷을 추적한다."""
        if not packet.haslayer(TCP):
            return None

        src_ip, dst_ip = get_ip_addrs(packet)
        if not src_ip or not dst_ip:
            return None

        tcp = packet[TCP]
        # SYN 패킷만 (연결 시도)
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
            return None

        dst_port = tcp.dport

        # 양쪽 모두 내부 IP여야 함
        if not is_internal(src_ip) or not is_internal(dst_ip):
            return None

        # 횡이동 포트여야 함
        if dst_port not in self._lateral_ports:
            return None

        now = time.time()
        self._lateral_connections[src_ip].append((now, dst_ip, dst_port))
        self._connection_graph[dst_ip].add(src_ip)

        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """고유 목적지 호스트 수와 연결 체인을 검사하여 횡이동 알림을 생성한다."""
        alerts = []
        now = time.time()
        cutoff = now - self._window

        keys_to_delete = []
        for src_ip, connections in self._lateral_connections.items():
            # 오래된 항목 제거
            while connections and connections[0][0] < cutoff:
                connections.popleft()

            if not connections:
                keys_to_delete.append(src_ip)
                continue

            # 고유 목적지 호스트 수 계산
            unique_hosts = set(dst for _, dst, _ in connections)
            last_alert = self._alerted.get(src_ip, 0)

            if (
                len(unique_hosts) >= self._unique_host_threshold
                and now - last_alert > self._window
            ):
                self._alerted[src_ip] = now
                ports_accessed = set(port for _, _, port in connections)
                confidence = min(1.0, 0.6 + len(unique_hosts) * 0.05)
                alerts.append(Alert(
                    engine=self.name,
                    severity=Severity.CRITICAL,
                    title="Lateral Movement Detected",
                    description=(
                        f"Internal host {src_ip} accessed lateral ports on "
                        f"{len(unique_hosts)} unique internal hosts in "
                        f"{self._window}s. Ports: {sorted(ports_accessed)}"
                    ),
                    source_ip=src_ip,
                    confidence=confidence,
                    metadata={
                        "unique_hosts": len(unique_hosts),
                        "target_hosts": sorted(unique_hosts)[:10],
                        "ports_accessed": sorted(ports_accessed),
                        "window_seconds": self._window,
                    },
                ))

        for key in keys_to_delete:
            del self._lateral_connections[key]

        # 체인 탐지 (A가 B에, B가 C에 접속 등)
        for start_ip in list(self._connection_graph.keys()):
            chain = self._find_chain(start_ip, set())
            if len(chain) > self._chain_depth_threshold:
                chain_key = "->".join(chain)
                if chain_key not in self._chain_alerted:
                    self._chain_alerted.add(chain_key)
                    alerts.append(Alert(
                        engine=self.name,
                        severity=Severity.CRITICAL,
                        title="Connection Chain Detected",
                        description=(
                            f"Sequential connection chain detected: "
                            f"{' -> '.join(chain)} (depth: {len(chain)}). "
                            "This pattern is indicative of lateral movement."
                        ),
                        source_ip=chain[0],
                        confidence=0.8,
                        metadata={
                            "chain": chain,
                            "depth": len(chain),
                        },
                    ))

        # 오래된 쿨다운 제거
        expired = [k for k, v in self._alerted.items() if now - v > self._window * 2]
        for k in expired:
            del self._alerted[k]

        # 오래된 체인 데이터 주기적 정리
        if len(self._connection_graph) > 1000:
            self._connection_graph.clear()
            self._chain_alerted.clear()

        return alerts

    def _find_chain(self, current: str, visited: set[str], depth: int = 0) -> list[str]:
        """현재 노드에서 시작하는 가장 긴 연결 체인을 찾는다."""
        if depth > 10 or current in visited:
            return [current]
        visited.add(current)

        # 현재 노드가 다른 호스트에 대한 연결을 시작했는지 확인
        best_chain = [current]
        if current in self._lateral_connections:
            targets = set(dst for _, dst, _ in self._lateral_connections[current])
            for target in targets:
                if target not in visited:
                    sub_chain = self._find_chain(target, visited, depth + 1)
                    candidate = [current] + sub_chain
                    if len(candidate) > len(best_chain):
                        best_chain = candidate

        visited.discard(current)
        return best_chain

    def shutdown(self) -> None:
        """엔진 종료 시 모든 추적 데이터를 정리한다."""
        self._lateral_connections.clear()
        self._connection_graph.clear()
        self._alerted.clear()
        self._chain_alerted.clear()
