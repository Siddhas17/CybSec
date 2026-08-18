"""Graph, node, and edge statistics for the aggregated attack-communication
graph.

Terminology note (see docs/attack_graph.md "Limitations"): CICIDS2017 is
flow data captured in a lab testbed, not a ground-truth multi-stage attack
campaign graph. Functions here describe an "attack-related communication
graph" -- observed source/destination structure annotated with attack
statistics. None of this asserts that a connected path is a real attack
chain, and nothing here is a risk score.
"""

from __future__ import annotations

from collections import Counter

import networkx as nx


def annotate_degree_metrics(graph: nx.DiGraph) -> None:
    """Set structural node attributes derived purely from graph topology:
    in_degree, out_degree, degree, unique_source_count, unique_destination_count.

    In this aggregated model, edges are collapsed per unique (src_ip,
    dst_ip) pair, so a node's in_degree already equals its count of
    distinct predecessors (unique_source_count) and out_degree already
    equals its count of distinct successors (unique_destination_count) --
    the two pairs are aliases of each other by construction, both are set
    for direct availability as documented node attributes.
    """
    for node in graph.nodes:
        in_deg = graph.in_degree(node)
        out_deg = graph.out_degree(node)
        graph.nodes[node]["in_degree"] = in_deg
        graph.nodes[node]["out_degree"] = out_deg
        graph.nodes[node]["degree"] = in_deg + out_deg
        graph.nodes[node]["unique_source_count"] = in_deg
        graph.nodes[node]["unique_destination_count"] = out_deg


def summarize_graph(graph: nx.DiGraph) -> dict:
    """Whole-graph summary: counts, flow totals, attack ratio, degree
    averages, and weakly-connected-component structure.

    Connected components use *weak* connectivity (edges treated as
    undirected for reachability) -- the natural notion for "who is part of
    the same communication cluster" in a directed src->dst graph; strong
    connectivity (mutual reachability) is rarely meaningful here since most
    flow pairs are one-directional.
    """
    total_flows = sum(d["flow_count"] for _, _, d in graph.edges(data=True))
    benign_flows = sum(d["benign_flow_count"] for _, _, d in graph.edges(data=True))
    attack_flows = sum(d["attack_flow_count"] for _, _, d in graph.edges(data=True))

    components = sorted(
        (len(c) for c in nx.weakly_connected_components(graph)), reverse=True
    )
    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()

    return {
        "node_count": node_count,
        "edge_count": edge_count,
        "total_flows": total_flows,
        "benign_flows": benign_flows,
        "attack_flows": attack_flows,
        "attack_flow_ratio": round(attack_flows / total_flows, 6) if total_flows else 0.0,
        "avg_in_degree": round(edge_count / node_count, 4) if node_count else 0.0,
        "avg_out_degree": round(edge_count / node_count, 4) if node_count else 0.0,
        "weakly_connected_component_count": len(components),
        "largest_component_size": components[0] if components else 0,
        "component_size_distribution_top10": components[:10],
    }


def nodes_involved_in_attack_traffic(graph: nx.DiGraph) -> list[str]:
    return [n for n, d in graph.nodes(data=True) if d.get("attack_flow_count", 0) > 0]


def high_activity_nodes(graph: nx.DiGraph, n: int = 10) -> list[dict]:
    """Top-N nodes by total_flow_count -- pure activity volume, not an
    attack or risk indicator on its own."""
    ranked = sorted(
        graph.nodes(data=True), key=lambda item: item[1].get("total_flow_count", 0), reverse=True
    )
    return [{"ip": ip, **data} for ip, data in ranked[:n]]


def top_attack_sources(graph: nx.DiGraph, n: int = 10) -> list[dict]:
    """Top-N nodes by attack_flow_count where the node appears as a source
    on at least one attack-carrying edge."""
    counts: Counter[str] = Counter()
    for src, _, d in graph.edges(data=True):
        counts[src] += d.get("attack_flow_count", 0)
    ranked = [(ip, c) for ip, c in counts.items() if c > 0]
    ranked.sort(key=lambda item: item[1], reverse=True)
    return [{"ip": ip, "attack_flow_count": c} for ip, c in ranked[:n]]


def top_attack_destinations(graph: nx.DiGraph, n: int = 10) -> list[dict]:
    """Top-N nodes by attack_flow_count where the node appears as a
    destination on at least one attack-carrying edge -- i.e. destinations
    receiving many attack flows."""
    counts: Counter[str] = Counter()
    for _, dst, d in graph.edges(data=True):
        counts[dst] += d.get("attack_flow_count", 0)
    ranked = [(ip, c) for ip, c in counts.items() if c > 0]
    ranked.sort(key=lambda item: item[1], reverse=True)
    return [{"ip": ip, "attack_flow_count": c} for ip, c in ranked[:n]]


def sources_with_many_destinations(graph: nx.DiGraph, n: int = 10) -> list[dict]:
    """Top-N source nodes by number of distinct destinations contacted
    (out_degree) -- e.g. scan-like fan-out behavior, not itself an attack
    verdict."""
    ranked = sorted(graph.out_degree(), key=lambda item: item[1], reverse=True)
    return [{"ip": ip, "unique_destination_count": deg} for ip, deg in ranked[:n]]


def high_attack_ratio_edges(graph: nx.DiGraph, min_flow_count: int = 5, n: int = 10) -> list[dict]:
    """Top-N edges by attack_ratio, restricted to edges with at least
    min_flow_count total flows (a single-flow 100%-attack edge is not
    meaningful on its own, so a minimum volume threshold is required --
    documented filter, not a hidden default) and attack_ratio > 0 (never
    pads the result with purely-benign edges just to reach N)."""
    candidates = [
        {"src_ip": u, "dst_ip": v, **d}
        for u, v, d in graph.edges(data=True)
        if d.get("flow_count", 0) >= min_flow_count and d.get("attack_ratio", 0) > 0
    ]
    candidates.sort(key=lambda e: e["attack_ratio"], reverse=True)
    return candidates[:n]


def attack_type_distribution(graph: nx.DiGraph) -> dict[str, int]:
    """Count of distinct edges each canonical attack label appears on
    (an edge with two attack types seen contributes to both counts). This
    is edge-presence counting, not a per-flow breakdown -- EdgeAccumulator
    tracks attack_flow_count in aggregate per edge, not split per label."""
    counter: Counter[str] = Counter()
    for _, _, d in graph.edges(data=True):
        for label in d.get("attack_labels", []):
            counter[label] += 1
    return dict(counter.most_common())
