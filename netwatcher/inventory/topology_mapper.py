"""네트워크 토폴로지 그래프 구축 모듈.

관찰된 트래픽으로부터 D3.js 호환 그래프를 생성한다.
외부 의존성(networkx 등) 없이 plain dict로 구현.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field


@dataclass
class TopologyNode:
    """토폴로지 그래프의 노드(호스트)."""

    ip:              str
    mac:             str
    first_seen:      float
    last_seen:       float
    device_type:     str = "unknown"
    hostname:        str = ""
    connections_in:  int = 0
    connections_out: int = 0


@dataclass
class TopologyEdge:
    """토폴로지 그래프의 엣지(연결)."""

    src_ip:       str
    dst_ip:       str
    protocol:     str
    dst_port:     int
    bytes_total:  int   = 0
    packet_count: int   = 0
    first_seen:   float = 0.0
    last_seen:    float = 0.0


class TopologyMapper:
    """관찰된 트래픽으로부터 네트워크 토폴로지를 구축한다.

    메모리 바운드: max_nodes/max_edges를 초과하면 LRU 방식으로 제거.
    edge_ttl 초과 엣지는 prune_expired()로 정리.
    """

    def __init__(
        self,
        max_nodes: int   = 10_000,
        max_edges: int   = 50_000,
        edge_ttl:  float = 3600.0,
    ) -> None:
        self._max_nodes = max(16, max_nodes)
        self._max_edges = max(16, max_edges)
        self._edge_ttl  = edge_ttl

        # LRU 순서를 유지하는 OrderedDict — 가장 최근 접근 항목이 끝
        self._nodes: OrderedDict[str, TopologyNode] = OrderedDict()
        self._edges: OrderedDict[tuple[str, str], TopologyEdge] = OrderedDict()

    # ------------------------------------------------------------------
    # 기록
    # ------------------------------------------------------------------

    def record_connection(
        self,
        src_mac:     str,
        src_ip:      str,
        dst_mac:     str,
        dst_ip:      str,
        protocol:    str,
        dst_port:    int,
        bytes_count: int,
    ) -> None:
        """패킷 관찰 시 호출. 노드와 엣지를 갱신한다."""
        now = time.time()

        # 노드 upsert — src
        self._upsert_node(src_ip, src_mac, now, connections_out_delta=1)
        # 노드 upsert — dst
        self._upsert_node(dst_ip, dst_mac, now, connections_in_delta=1)

        # 엣지 upsert
        edge_key = (src_ip, dst_ip)
        if edge_key in self._edges:
            self._edges.move_to_end(edge_key)
            edge = self._edges[edge_key]
            edge.bytes_total  += bytes_count
            edge.packet_count += 1
            edge.last_seen     = now
            # 프로토콜/포트는 마지막 관찰값으로 갱신
            edge.protocol = protocol
            edge.dst_port = dst_port
        else:
            self._evict_edges_if_needed()
            self._edges[edge_key] = TopologyEdge(
                src_ip       = src_ip,
                dst_ip       = dst_ip,
                protocol     = protocol,
                dst_port     = dst_port,
                bytes_total  = bytes_count,
                packet_count = 1,
                first_seen   = now,
                last_seen    = now,
            )

    # ------------------------------------------------------------------
    # 조회
    # ------------------------------------------------------------------

    def get_graph(self) -> dict:
        """D3.js force-directed graph 호환 형식으로 반환한다.

        Returns:
            {"nodes": [...], "links": [...]}
        """
        nodes_list = []
        for ip, node in self._nodes.items():
            nodes_list.append({
                "id":              ip,
                "mac":             node.mac,
                "device_type":     node.device_type,
                "hostname":        node.hostname,
                "first_seen":      node.first_seen,
                "last_seen":       node.last_seen,
                "connections_in":  node.connections_in,
                "connections_out": node.connections_out,
            })

        links_list = []
        for (src, dst), edge in self._edges.items():
            links_list.append({
                "source":       src,
                "target":       dst,
                "protocol":     edge.protocol,
                "dst_port":     edge.dst_port,
                "bytes_total":  edge.bytes_total,
                "packet_count": edge.packet_count,
                "first_seen":   edge.first_seen,
                "last_seen":    edge.last_seen,
            })

        return {"nodes": nodes_list, "links": links_list}

    def get_node(self, ip: str) -> dict | None:
        """특정 IP의 노드 정보를 반환한다. 없으면 None."""
        node = self._nodes.get(ip)
        if node is None:
            return None
        return {
            "ip":              node.ip,
            "mac":             node.mac,
            "device_type":     node.device_type,
            "hostname":        node.hostname,
            "first_seen":      node.first_seen,
            "last_seen":       node.last_seen,
            "connections_in":  node.connections_in,
            "connections_out": node.connections_out,
        }

    def get_neighbors(self, ip: str) -> list[dict]:
        """특정 IP의 이웃 노드(인접 호스트) 목록을 반환한다."""
        neighbor_ips: set[str] = set()
        for (src, dst) in self._edges:
            if src == ip:
                neighbor_ips.add(dst)
            elif dst == ip:
                neighbor_ips.add(src)

        result = []
        for nip in neighbor_ips:
            node_dict = self.get_node(nip)
            if node_dict:
                result.append(node_dict)
        return result

    # ------------------------------------------------------------------
    # 정리
    # ------------------------------------------------------------------

    def prune_expired(self) -> int:
        """edge_ttl을 초과한 엣지를 제거한다. 제거된 수 반환.

        엣지 제거 후 어떤 엣지에도 참여하지 않는 고립 노드도 제거.
        """
        cutoff  = time.time() - self._edge_ttl
        expired = [
            key for key, edge in self._edges.items()
            if edge.last_seen < cutoff
        ]
        for key in expired:
            del self._edges[key]

        # 고립 노드 정리
        active_ips: set[str] = set()
        for src, dst in self._edges:
            active_ips.add(src)
            active_ips.add(dst)
        orphan_ips = [ip for ip in self._nodes if ip not in active_ips]
        for ip in orphan_ips:
            del self._nodes[ip]

        return len(expired)

    # ------------------------------------------------------------------
    # 게이트웨이 탐지
    # ------------------------------------------------------------------

    def detect_gateway_nodes(self) -> list[str]:
        """높은 degree centrality를 가진 노드를 게이트웨이 후보로 반환한다.

        degree = connections_in + connections_out
        상위 노드 중 degree가 전체 노드 수의 30% 이상이면 게이트웨이 후보.
        최소 1개 이상의 연결이 있어야 한다.
        """
        if not self._nodes:
            return []

        scored: list[tuple[str, int]] = []
        for ip, node in self._nodes.items():
            degree = node.connections_in + node.connections_out
            if degree > 0:
                scored.append((ip, degree))

        if not scored:
            return []

        scored.sort(key=lambda x: x[1], reverse=True)
        n_nodes   = len(self._nodes)
        threshold = max(3, int(n_nodes * 0.3))

        return [ip for ip, degree in scored if degree >= threshold]

    # ------------------------------------------------------------------
    # 노드 메타데이터 갱신
    # ------------------------------------------------------------------

    def update_node_metadata(
        self,
        ip:          str,
        device_type: str | None = None,
        hostname:    str | None = None,
    ) -> None:
        """외부(device_classifier, hostname_resolver 등)에서 메타데이터를 보강한다."""
        node = self._nodes.get(ip)
        if node is None:
            return
        if device_type is not None:
            node.device_type = device_type
        if hostname is not None:
            node.hostname = hostname

    # ------------------------------------------------------------------
    # 통계
    # ------------------------------------------------------------------

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ------------------------------------------------------------------
    # 내부
    # ------------------------------------------------------------------

    def _upsert_node(
        self,
        ip:  str,
        mac: str,
        now: float,
        connections_in_delta:  int = 0,
        connections_out_delta: int = 0,
    ) -> None:
        if ip in self._nodes:
            self._nodes.move_to_end(ip)
            node = self._nodes[ip]
            node.last_seen        = now
            node.mac              = mac  # MAC 갱신 (동일 IP 다른 MAC 가능)
            node.connections_in  += connections_in_delta
            node.connections_out += connections_out_delta
        else:
            self._evict_nodes_if_needed()
            self._nodes[ip] = TopologyNode(
                ip              = ip,
                mac             = mac,
                first_seen      = now,
                last_seen       = now,
                connections_in  = connections_in_delta,
                connections_out = connections_out_delta,
            )

    def _evict_nodes_if_needed(self) -> None:
        """노드 수가 max_nodes에 도달하면 가장 오래된 25%를 제거한다."""
        if len(self._nodes) < self._max_nodes:
            return
        n_remove = max(1, len(self._nodes) // 4)
        for _ in range(n_remove):
            self._nodes.popitem(last=False)

    def _evict_edges_if_needed(self) -> None:
        """엣지 수가 max_edges에 도달하면 가장 오래된 25%를 제거한다."""
        if len(self._edges) < self._max_edges:
            return
        n_remove = max(1, len(self._edges) // 4)
        for _ in range(n_remove):
            self._edges.popitem(last=False)
