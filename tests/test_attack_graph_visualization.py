"""Tests for subgraph selection strategies and a smoke test that draw_graph
produces a file without erroring. Does not inspect pixel content."""

import networkx as nx
import pytest

from attack_graph.visualization.visualize_graph import (
    draw_graph,
    select_min_attack_threshold,
    select_neighborhood,
    select_subgraph,
    select_top_attack_edges,
)


@pytest.fixture
def sample_graph():
    g = nx.DiGraph()
    for ip, attack in [("A", 3), ("B", 7), ("C", 6), ("D", 0)]:
        g.add_node(ip, ip=ip, total_flow_count=10, attack_flow_count=attack)
    g.add_edge("A", "B", flow_count=10, attack_flow_count=2, attack_ratio=0.2)
    g.add_edge("B", "C", flow_count=5, attack_flow_count=5, attack_ratio=1.0)
    g.add_edge("A", "D", flow_count=20, attack_flow_count=0, attack_ratio=0.0)
    return g


def test_select_top_attack_edges_excludes_benign_only_edges(sample_graph):
    sub = select_top_attack_edges(sample_graph, n=10)
    assert set(sub.edges) == {("A", "B"), ("B", "C")}
    assert ("A", "D") not in sub.edges


def test_select_top_attack_edges_respects_n(sample_graph):
    sub = select_top_attack_edges(sample_graph, n=1)
    assert sub.number_of_edges() == 1
    assert ("B", "C") in sub.edges  # higher attack_flow_count than A->B


def test_select_min_attack_threshold(sample_graph):
    sub = select_min_attack_threshold(sample_graph, min_attack_flows=3)
    assert set(sub.edges) == {("B", "C")}


def test_select_neighborhood_includes_only_touching_edges(sample_graph):
    sub = select_neighborhood(sample_graph, "A", max_edges=10)
    assert set(sub.edges) == {("A", "B"), ("A", "D")}
    assert "C" not in sub.nodes


def test_select_subgraph_dispatches_by_strategy_name(sample_graph):
    sub = select_subgraph(sample_graph, strategy="min_attack_threshold", min_attack_flows=5)
    assert set(sub.edges) == {("B", "C")}


def test_select_subgraph_rejects_unknown_strategy(sample_graph):
    with pytest.raises(ValueError):
        select_subgraph(sample_graph, strategy="not-a-real-strategy")


def test_draw_graph_writes_a_file(tmp_path, sample_graph):
    sub = select_top_attack_edges(sample_graph, n=10)
    out_path = tmp_path / "viz" / "sample.png"
    draw_graph(sub, out_path, title="Test Graph")

    assert out_path.exists()
    assert out_path.stat().st_size > 0


def test_draw_graph_rejects_empty_subgraph():
    empty = nx.DiGraph()
    with pytest.raises(ValueError):
        draw_graph(empty, "unused.png")
