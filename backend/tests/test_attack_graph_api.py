"""Section 16: graph endpoint, backed by a tiny synthetic persisted graph
(never the real ~114K-edge graph in ordinary tests)."""

from __future__ import annotations

import networkx as nx

from backend.app.services.graph_service import persist_graph


def _build_synthetic_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("1.1.1.1", total_flow_count=10, benign_flow_count=8, attack_flow_count=2, attack_ratio=0.2, in_degree=0, out_degree=1, degree=1)
    g.add_node("2.2.2.2", total_flow_count=15, benign_flow_count=5, attack_flow_count=10, attack_ratio=0.667, in_degree=1, out_degree=1, degree=2)
    g.add_node("3.3.3.3", total_flow_count=5, benign_flow_count=0, attack_flow_count=5, attack_ratio=1.0, in_degree=1, out_degree=0, degree=1)
    g.add_edge(
        "1.1.1.1", "2.2.2.2", flow_count=10, benign_flow_count=8, attack_flow_count=2, attack_ratio=0.2,
        unique_source_ports=3, unique_destination_ports=2, protocols_seen=[6],
        first_seen="2017-07-03T00:00:00", last_seen="2017-07-03T01:00:00",
        total_forward_bytes=100, total_backward_bytes=50, attack_labels=["DDoS"],
    )
    g.add_edge(
        "2.2.2.2", "3.3.3.3", flow_count=5, benign_flow_count=0, attack_flow_count=5, attack_ratio=1.0,
        unique_source_ports=1, unique_destination_ports=1, protocols_seen=[6],
        first_seen="2017-07-03T00:00:00", last_seen="2017-07-03T02:00:00",
        total_forward_bytes=200, total_backward_bytes=20, attack_labels=["PortScan"],
    )
    return g


def test_attack_graph_endpoint_returns_persisted_data(client, auth_headers, db_session):
    persist_graph(db_session, _build_synthetic_graph())

    response = client.get("/api/v1/attack-graph", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total_node_count"] == 3
    assert body["total_edge_count"] == 2
    assert len(body["edges"]) == 2
    edge_pairs = {(e["src_ip"], e["dst_ip"]) for e in body["edges"]}
    assert ("1.1.1.1", "2.2.2.2") in edge_pairs


def test_attack_graph_min_attack_flow_count_filter(client, auth_headers, db_session):
    persist_graph(db_session, _build_synthetic_graph())

    response = client.get("/api/v1/attack-graph", params={"min_attack_flow_count": 5}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["returned_edge_count"] == 1
    assert body["edges"][0]["dst_ip"] == "3.3.3.3"


def test_attack_graph_neighborhood_filter(client, auth_headers, db_session):
    persist_graph(db_session, _build_synthetic_graph())

    response = client.get("/api/v1/attack-graph", params={"node_ip": "2.2.2.2"}, headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["returned_edge_count"] == 2  # both edges touch 2.2.2.2
