"""TopologyMapper 테스트: 그래프 구축, D3 형식, 게이트웨이 탐지, 프루닝."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from netwatcher.inventory.topology_mapper import TopologyEdge, TopologyMapper, TopologyNode


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _record(mapper: TopologyMapper, src_ip: str = "10.0.0.1", dst_ip: str = "10.0.0.2", **kw):
    """기본값으로 연결을 기록하는 헬퍼."""
    defaults = {
        "src_mac":     "aa:bb:cc:dd:ee:01",
        "src_ip":      src_ip,
        "dst_mac":     "aa:bb:cc:dd:ee:02",
        "dst_ip":      dst_ip,
        "protocol":    "TCP",
        "dst_port":    80,
        "bytes_count": 100,
    }
    defaults.update(kw)
    mapper.record_connection(**defaults)


# ---------------------------------------------------------------------------
# 노드/엣지 생성
# ---------------------------------------------------------------------------

class TestRecordConnection:
    def test_creates_two_nodes(self):
        m = TopologyMapper()
        _record(m)
        assert m.node_count == 2

    def test_creates_one_edge(self):
        m = TopologyMapper()
        _record(m)
        assert m.edge_count == 1

    def test_duplicate_connection_updates_counters(self):
        m = TopologyMapper()
        _record(m)
        _record(m, bytes_count=200)
        assert m.edge_count == 1
        graph = m.get_graph()
        link  = graph["links"][0]
        assert link["bytes_total"] == 300
        assert link["packet_count"] == 2

    def test_reverse_direction_is_separate_edge(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        _record(m, src_ip="10.0.0.2", dst_ip="10.0.0.1")
        assert m.edge_count == 2

    def test_connection_in_out_counts(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        src_node = m.get_node("10.0.0.1")
        dst_node = m.get_node("10.0.0.2")
        assert src_node["connections_out"] == 1
        assert dst_node["connections_in"] == 1


# ---------------------------------------------------------------------------
# D3.js 형식 출력
# ---------------------------------------------------------------------------

class TestGetGraph:
    def test_empty_graph(self):
        m     = TopologyMapper()
        graph = m.get_graph()
        assert graph == {"nodes": [], "links": []}

    def test_graph_structure(self):
        m = TopologyMapper()
        _record(m)
        graph = m.get_graph()

        assert len(graph["nodes"]) == 2
        assert len(graph["links"]) == 1

        node_keys = {"id", "mac", "device_type", "hostname", "first_seen",
                     "last_seen", "connections_in", "connections_out"}
        for node in graph["nodes"]:
            assert set(node.keys()) == node_keys

        link_keys = {"source", "target", "protocol", "dst_port",
                     "bytes_total", "packet_count", "first_seen", "last_seen"}
        for link in graph["links"]:
            assert set(link.keys()) == link_keys

    def test_node_ids_match_ips(self):
        m = TopologyMapper()
        _record(m, src_ip="192.168.1.1", dst_ip="192.168.1.2")
        graph   = m.get_graph()
        node_ids = {n["id"] for n in graph["nodes"]}
        assert node_ids == {"192.168.1.1", "192.168.1.2"}


# ---------------------------------------------------------------------------
# 노드 조회
# ---------------------------------------------------------------------------

class TestGetNode:
    def test_existing_node(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.5")
        node = m.get_node("10.0.0.5")
        assert node is not None
        assert node["ip"] == "10.0.0.5"

    def test_missing_node_returns_none(self):
        m = TopologyMapper()
        assert m.get_node("10.0.0.99") is None


class TestGetNeighbors:
    def test_returns_direct_neighbors(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        _record(m, src_ip="10.0.0.1", dst_ip="10.0.0.3")
        _record(m, src_ip="10.0.0.4", dst_ip="10.0.0.1")

        neighbors = m.get_neighbors("10.0.0.1")
        neighbor_ips = {n["ip"] for n in neighbors}
        assert neighbor_ips == {"10.0.0.2", "10.0.0.3", "10.0.0.4"}

    def test_isolated_node_has_no_neighbors(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.1", dst_ip="10.0.0.2")
        neighbors = m.get_neighbors("10.0.0.99")
        assert neighbors == []


# ---------------------------------------------------------------------------
# 게이트웨이 탐지
# ---------------------------------------------------------------------------

class TestDetectGatewayNodes:
    def test_empty_graph_no_gateways(self):
        m = TopologyMapper()
        assert m.detect_gateway_nodes() == []

    def test_hub_node_detected_as_gateway(self):
        """허브 노드(많은 연결)는 게이트웨이로 탐지되어야 한다."""
        m = TopologyMapper()
        # 10.0.0.1 → 10개 목적지 (degree=10 out)
        for i in range(2, 12):
            _record(m, src_ip="10.0.0.1", dst_ip=f"10.0.0.{i}")
        # 총 11 노드, threshold = max(3, 11*0.3) = 3
        # 10.0.0.1 degree = 10 >= 3 → 게이트웨이
        gateways = m.detect_gateway_nodes()
        assert "10.0.0.1" in gateways

    def test_leaf_nodes_not_gateway(self):
        """리프 노드(연결 1개)는 게이트웨이가 아니다."""
        m = TopologyMapper()
        for i in range(2, 12):
            _record(m, src_ip="10.0.0.1", dst_ip=f"10.0.0.{i}")
        gateways = m.detect_gateway_nodes()
        # 리프 노드 (degree=1) < threshold(3)
        assert "10.0.0.5" not in gateways


# ---------------------------------------------------------------------------
# 만료 엣지 정리 (prune)
# ---------------------------------------------------------------------------

class TestPruneExpired:
    def test_no_expired_edges(self):
        m = TopologyMapper(edge_ttl=3600)
        _record(m)
        removed = m.prune_expired()
        assert removed == 0
        assert m.edge_count == 1

    def test_expired_edges_removed(self):
        m = TopologyMapper(edge_ttl=60)
        with patch("netwatcher.inventory.topology_mapper.time") as mock_time:
            mock_time.time.return_value = 1000.0
            _record(m)
            # 시간을 TTL 이후로 이동
            mock_time.time.return_value = 1000.0 + 120.0
            removed = m.prune_expired()
        assert removed == 1
        assert m.edge_count == 0

    def test_orphan_nodes_cleaned_after_prune(self):
        """엣지 제거 후 고립 노드도 제거되어야 한다."""
        m = TopologyMapper(edge_ttl=60)
        with patch("netwatcher.inventory.topology_mapper.time") as mock_time:
            mock_time.time.return_value = 1000.0
            _record(m, src_ip="10.0.0.1", dst_ip="10.0.0.2")
            assert m.node_count == 2
            mock_time.time.return_value = 1000.0 + 120.0
            m.prune_expired()
        assert m.node_count == 0


# ---------------------------------------------------------------------------
# 메모리 바운드 (LRU eviction)
# ---------------------------------------------------------------------------

class TestMemoryBounds:
    def test_node_eviction(self):
        """max_nodes 초과 시 가장 오래된 노드가 제거되어야 한다."""
        m = TopologyMapper(max_nodes=20, max_edges=50_000)
        for i in range(30):
            _record(m, src_ip=f"10.0.{i}.1", dst_ip=f"10.0.{i}.2")
        # 각 record_connection은 2개 노드 생성 → 최대 60개 시도
        # eviction 발생하여 max_nodes 이하로 유지
        assert m.node_count <= 20

    def test_edge_eviction(self):
        """max_edges 초과 시 가장 오래된 엣지가 제거되어야 한다."""
        m = TopologyMapper(max_nodes=10_000, max_edges=20)
        for i in range(30):
            _record(m, src_ip=f"10.0.0.{i}", dst_ip=f"10.0.1.{i}")
        assert m.edge_count <= 20


# ---------------------------------------------------------------------------
# 메타데이터 갱신
# ---------------------------------------------------------------------------

class TestUpdateNodeMetadata:
    def test_update_device_type(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.1")
        m.update_node_metadata("10.0.0.1", device_type="router")
        node = m.get_node("10.0.0.1")
        assert node["device_type"] == "router"

    def test_update_hostname(self):
        m = TopologyMapper()
        _record(m, src_ip="10.0.0.1")
        m.update_node_metadata("10.0.0.1", hostname="gateway.local")
        node = m.get_node("10.0.0.1")
        assert node["hostname"] == "gateway.local"

    def test_update_nonexistent_node_no_error(self):
        m = TopologyMapper()
        m.update_node_metadata("10.0.0.99", device_type="server")
        # 에러 없이 무시
