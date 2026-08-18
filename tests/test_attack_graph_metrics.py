"""Unit tests for attack_graph.analysis.graph_metrics against a small,
hand-built graph (not routed through build_graph) so the metrics logic is
verified independently of aggregation."""

import networkx as nx
import pytest

from attack_graph.analysis.graph_metrics import (
    annotate_degree_metrics,
    attack_type_distribution,
    high_activity_nodes,
    high_attack_ratio_edges,
    nodes_involved_in_attack_traffic,
    sources_with_many_destinations,
    summarize_graph,
    top_attack_destinations,
    top_attack_sources,
)


@pytest.fixture
def sample_graph():
    g = nx.DiGraph()
    g.add_node("A", ip="A", total_flow_count=11, benign_flow_count=8, attack_flow_count=3, attack_ratio=3 / 11)
    g.add_node("B", ip="B", total_flow_count=15, benign_flow_count=8, attack_flow_count=7, attack_ratio=7 / 15)
    g.add_node("C", ip="C", total_flow_count=6, benign_flow_count=0, attack_flow_count=6, attack_ratio=1.0)
    g.add_node("D", ip="D", total_flow_count=0, benign_flow_count=0, attack_flow_count=0, attack_ratio=0.0)

    g.add_edge("A", "B", flow_count=10, benign_flow_count=8, attack_flow_count=2, attack_ratio=0.2, attack_labels=["DDoS"])
    g.add_edge("B", "C", flow_count=5, benign_flow_count=0, attack_flow_count=5, attack_ratio=1.0, attack_labels=["PortScan"])
    g.add_edge("A", "C", flow_count=1, benign_flow_count=0, attack_flow_count=1, attack_ratio=1.0, attack_labels=["Bot"])
    return g


def test_annotate_degree_metrics(sample_graph):
    annotate_degree_metrics(sample_graph)

    assert sample_graph.nodes["A"]["in_degree"] == 0
    assert sample_graph.nodes["A"]["out_degree"] == 2
    assert sample_graph.nodes["A"]["degree"] == 2
    assert sample_graph.nodes["A"]["unique_destination_count"] == 2

    assert sample_graph.nodes["C"]["in_degree"] == 2
    assert sample_graph.nodes["C"]["out_degree"] == 0
    assert sample_graph.nodes["C"]["unique_source_count"] == 2

    assert sample_graph.nodes["D"]["in_degree"] == 0
    assert sample_graph.nodes["D"]["out_degree"] == 0


def test_summarize_graph_totals_and_components(sample_graph):
    summary = summarize_graph(sample_graph)

    assert summary["node_count"] == 4
    assert summary["edge_count"] == 3
    assert summary["total_flows"] == 16
    assert summary["benign_flows"] == 8
    assert summary["attack_flows"] == 8
    assert summary["attack_flow_ratio"] == pytest.approx(0.5)
    assert summary["weakly_connected_component_count"] == 2
    assert summary["largest_component_size"] == 3


def test_nodes_involved_in_attack_traffic_excludes_pure_benign(sample_graph):
    involved = nodes_involved_in_attack_traffic(sample_graph)
    assert set(involved) == {"A", "B", "C"}
    assert "D" not in involved


def test_high_activity_nodes_ranked_by_total_flow_count(sample_graph):
    top = high_activity_nodes(sample_graph, n=2)
    assert [n["ip"] for n in top] == ["B", "A"]


def test_top_attack_sources_and_destinations(sample_graph):
    sources = top_attack_sources(sample_graph, n=5)
    assert [s["ip"] for s in sources] == ["B", "A"]
    assert sources[0]["attack_flow_count"] == 5

    destinations = top_attack_destinations(sample_graph, n=5)
    assert [d["ip"] for d in destinations] == ["C", "B"]
    assert destinations[0]["attack_flow_count"] == 6


def test_sources_with_many_destinations(sample_graph):
    ranked = sources_with_many_destinations(sample_graph, n=5)
    assert ranked[0]["ip"] == "A"
    assert ranked[0]["unique_destination_count"] == 2


def test_high_attack_ratio_edges_respects_min_flow_count_threshold(sample_graph):
    # A->C has attack_ratio 1.0 but only 1 flow -- excluded by the threshold.
    edges = high_attack_ratio_edges(sample_graph, min_flow_count=5, n=5)
    pairs = [(e["src_ip"], e["dst_ip"]) for e in edges]

    assert ("A", "C") not in pairs
    assert pairs[0] == ("B", "C")  # ratio 1.0 ranks above A->B's 0.2


def test_attack_type_distribution_counts_edge_presence(sample_graph):
    dist = attack_type_distribution(sample_graph)
    assert dist == {"DDoS": 1, "PortScan": 1, "Bot": 1}
