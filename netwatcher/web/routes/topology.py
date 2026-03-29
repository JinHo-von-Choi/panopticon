"""토폴로지 및 위험도 REST API.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from netwatcher.inventory.topology_mapper import TopologyMapper
from netwatcher.inventory.dynamic_risk import DynamicRiskScorer


def create_topology_router(
    topology_mapper: TopologyMapper,
    risk_scorer: DynamicRiskScorer,
) -> APIRouter:
    """토폴로지/위험도 라우터를 생성한다."""
    router = APIRouter(prefix="/topology", tags=["topology"])

    @router.get("/graph")
    async def get_graph():
        """D3.js force-directed graph 형식의 전체 토폴로지 반환."""
        graph = topology_mapper.get_graph()
        return {
            "graph":      graph,
            "node_count": topology_mapper.node_count,
            "edge_count": topology_mapper.edge_count,
        }

    @router.get("/device/{ip}")
    async def get_device(ip: str):
        """특정 IP의 노드 상세 정보 및 이웃 목록."""
        node = topology_mapper.get_node(ip)
        if node is None:
            raise HTTPException(404, f"Node not found: {ip}")
        neighbors   = topology_mapper.get_neighbors(ip)
        risk_info   = risk_scorer.get_risk_summary(ip)
        return {
            "device":    node,
            "neighbors": neighbors,
            "risk":      risk_info,
        }

    @router.get("/gateways")
    async def get_gateways():
        """탐지된 게이트웨이 노드 목록."""
        gateway_ips = topology_mapper.detect_gateway_nodes()
        gateways    = []
        for ip in gateway_ips:
            node = topology_mapper.get_node(ip)
            if node:
                gateways.append(node)
        return {"gateways": gateways}

    @router.get("/high-risk")
    async def get_high_risk(
        threshold: float = Query(7.0, ge=0.0, le=10.0, description="위험 점수 임계값"),
    ):
        """임계값 이상의 고위험 디바이스 목록."""
        devices = risk_scorer.get_high_risk(threshold=threshold)
        return {"devices": devices, "threshold": threshold}

    return router
