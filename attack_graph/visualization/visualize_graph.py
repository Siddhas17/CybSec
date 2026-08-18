"""Subgraph selection and matplotlib rendering.

Selection strategies (documented, not hidden defaults):

- top_attack_edges: the N edges with the highest attack_flow_count.
- min_attack_threshold: every edge with attack_flow_count >= a threshold.
- neighborhood: every edge touching one chosen IP, capped at N by
  flow_count.

Rendering distinguishes attack-related vs. benign nodes/edges by color
only (a fixed 2-category legend) -- no severity gradient, no risk score.
Risk-based coloring belongs to a later phase.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")  # headless (WSL2 has no display server) -- must precede pyplot import

import math
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx

ATTACK_COLOR = "#d62728"
BENIGN_COLOR = "#4c72b0"
LAYOUT_SEED = 42


def _subgraph_from_edges(graph: nx.DiGraph, edges: list[tuple]) -> nx.DiGraph:
    sub = nx.DiGraph()
    for u, v, d in edges:
        sub.add_node(u, **graph.nodes[u])
        sub.add_node(v, **graph.nodes[v])
        sub.add_edge(u, v, **d)
    return sub


def select_top_attack_edges(graph: nx.DiGraph, n: int = 30) -> nx.DiGraph:
    """The N edges with the highest attack_flow_count (ties broken by
    attack_ratio). Edges with zero attack flows are never included."""
    ranked = sorted(
        graph.edges(data=True),
        key=lambda e: (e[2].get("attack_flow_count", 0), e[2].get("attack_ratio", 0)),
        reverse=True,
    )
    selected = [e for e in ranked if e[2].get("attack_flow_count", 0) > 0][:n]
    return _subgraph_from_edges(graph, selected)


def select_min_attack_threshold(graph: nx.DiGraph, min_attack_flows: int = 1) -> nx.DiGraph:
    """Every edge with attack_flow_count >= min_attack_flows."""
    selected = [
        (u, v, d) for u, v, d in graph.edges(data=True) if d.get("attack_flow_count", 0) >= min_attack_flows
    ]
    return _subgraph_from_edges(graph, selected)


def select_neighborhood(graph: nx.DiGraph, ip: str, max_edges: int = 50) -> nx.DiGraph:
    """Every edge touching `ip` as source or destination, capped at
    max_edges by flow_count (highest-volume edges kept first)."""
    edges = [(u, v, d) for u, v, d in graph.edges(data=True) if u == ip or v == ip]
    edges.sort(key=lambda e: e[2].get("flow_count", 0), reverse=True)
    return _subgraph_from_edges(graph, edges[:max_edges])


def select_subgraph(graph: nx.DiGraph, strategy: str = "top_attack_edges", **kwargs) -> nx.DiGraph:
    strategies = {
        "top_attack_edges": select_top_attack_edges,
        "min_attack_threshold": select_min_attack_threshold,
        "neighborhood": select_neighborhood,
    }
    if strategy not in strategies:
        raise ValueError(f"Unknown selection strategy {strategy!r}, choose from {sorted(strategies)}")
    return strategies[strategy](graph, **kwargs)


def draw_graph(subgraph: nx.DiGraph, output_path: Path, title: str = "Attack-Related Communication Graph") -> None:
    """Render `subgraph` to a PNG at output_path. Intended for small,
    already-filtered subgraphs (see select_subgraph) -- not the full
    dataset graph, which can have thousands of edges."""
    if subgraph.number_of_nodes() == 0:
        raise ValueError("Cannot visualize an empty subgraph")

    fig, ax = plt.subplots(figsize=(14, 10))
    pos = nx.spring_layout(subgraph, seed=LAYOUT_SEED, k=None)

    node_colors = [
        ATTACK_COLOR if data.get("attack_flow_count", 0) > 0 else BENIGN_COLOR
        for _, data in subgraph.nodes(data=True)
    ]
    node_sizes = [
        200 + 150 * math.log1p(data.get("total_flow_count", 0)) for _, data in subgraph.nodes(data=True)
    ]

    edge_colors = [
        ATTACK_COLOR if d.get("attack_flow_count", 0) > 0 else BENIGN_COLOR
        for _, _, d in subgraph.edges(data=True)
    ]
    edge_widths = [0.5 + 1.5 * math.log1p(d.get("flow_count", 0)) for _, _, d in subgraph.edges(data=True)]

    nx.draw_networkx_nodes(subgraph, pos, ax=ax, node_color=node_colors, node_size=node_sizes, alpha=0.9)
    nx.draw_networkx_edges(
        subgraph,
        pos,
        ax=ax,
        edge_color=edge_colors,
        width=edge_widths,
        arrows=True,
        arrowsize=12,
        connectionstyle="arc3,rad=0.08",
        alpha=0.7,
    )
    nx.draw_networkx_labels(subgraph, pos, ax=ax, font_size=7)

    legend_handles = [
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=ATTACK_COLOR, markersize=10, label="Attack-related (node/edge carried >=1 attack flow)"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=BENIGN_COLOR, markersize=10, label="Benign only"),
    ]
    ax.legend(handles=legend_handles, loc="upper left", fontsize=8)
    ax.set_title(
        f"{title}\n({subgraph.number_of_nodes()} nodes, {subgraph.number_of_edges()} edges shown -- "
        "not the full dataset graph; edge width ~ log(flow_count))",
        fontsize=10,
    )
    ax.axis("off")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
