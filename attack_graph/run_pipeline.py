"""End-to-end pipeline orchestration: build the graph from
ml/datasets/raw_labelled_flows/, compute analysis metrics, and write
compact artifacts to attack_graph/output/ (gitignored).

CLI usage (also serves as the Phase 2 performance test):
    python -m attack_graph.run_pipeline

Writes:
    attack_graph/output/graph_summary.json   build report + graph metrics + top lists
    attack_graph/output/node_stats.csv
    attack_graph/output/edge_stats.csv
    attack_graph/output/graph.graphml        full aggregated graph (small: one
                                              edge per unique src/dst pair)
    attack_graph/output/visualizations/top_attack_edges.png
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import networkx as nx

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
from attack_graph.config import GRAPH_OUTPUT_DIR, TOPOLOGY_RAW_DIR
from attack_graph.generation.build_graph import BuildReport, build_graph_from_directory
from attack_graph.visualization.visualize_graph import draw_graph, select_top_attack_edges

NODE_FIELDS = [
    "ip",
    "total_flow_count",
    "benign_flow_count",
    "attack_flow_count",
    "attack_ratio",
    "in_degree",
    "out_degree",
    "degree",
    "unique_source_count",
    "unique_destination_count",
]

EDGE_FIELDS = [
    "src_ip",
    "dst_ip",
    "flow_count",
    "benign_flow_count",
    "attack_flow_count",
    "attack_ratio",
    "unique_source_ports",
    "unique_destination_ports",
    "protocols_seen",
    "first_seen",
    "last_seen",
    "total_forward_bytes",
    "total_backward_bytes",
    "attack_labels",
]


def write_node_stats_csv(graph: nx.DiGraph, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=NODE_FIELDS)
        writer.writeheader()
        for ip, data in sorted(graph.nodes(data=True)):
            writer.writerow({field: data.get(field) for field in NODE_FIELDS if field != "ip"} | {"ip": ip})


def write_edge_stats_csv(graph: nx.DiGraph, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=EDGE_FIELDS)
        writer.writeheader()
        for src, dst, data in sorted(graph.edges(data=True)):
            row = {"src_ip": src, "dst_ip": dst}
            for field in EDGE_FIELDS:
                if field in ("src_ip", "dst_ip"):
                    continue
                value = data.get(field)
                if isinstance(value, list):
                    value = ";".join(str(v) for v in value)
                row[field] = value
            writer.writerow(row)


def write_graphml(graph: nx.DiGraph, path: Path) -> None:
    """GraphML attributes must be scalar -- list/None fields are stringified
    on a copy before serializing; the richer structured form stays
    available in edge_stats.csv / node_stats.csv / graph_summary.json."""
    safe = nx.DiGraph()
    for node, data in graph.nodes(data=True):
        safe.add_node(node, **{k: ("" if v is None else v) for k, v in data.items()})
    for u, v, data in graph.edges(data=True):
        clean = {}
        for k, val in data.items():
            if isinstance(val, list):
                clean[k] = ";".join(str(x) for x in val)
            elif val is None:
                clean[k] = ""
            else:
                clean[k] = val
        safe.add_edge(u, v, **clean)
    path.parent.mkdir(parents=True, exist_ok=True)
    nx.write_graphml(safe, path)


def run(
    raw_dir: Path = TOPOLOGY_RAW_DIR,
    output_dir: Path = GRAPH_OUTPUT_DIR,
    top_n: int = 15,
) -> tuple[nx.DiGraph, BuildReport, dict]:
    graph, build_report = build_graph_from_directory(raw_dir=raw_dir)
    annotate_degree_metrics(graph)

    analysis = {
        "graph_summary": summarize_graph(graph),
        "nodes_involved_in_attack_traffic_count": len(nodes_involved_in_attack_traffic(graph)),
        "high_activity_nodes": high_activity_nodes(graph, n=top_n),
        "top_attack_sources": top_attack_sources(graph, n=top_n),
        "top_attack_destinations": top_attack_destinations(graph, n=top_n),
        "sources_with_many_destinations": sources_with_many_destinations(graph, n=top_n),
        "high_attack_ratio_edges": high_attack_ratio_edges(graph, min_flow_count=5, n=top_n),
        "attack_type_distribution": attack_type_distribution(graph),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    write_node_stats_csv(graph, output_dir / "node_stats.csv")
    write_edge_stats_csv(graph, output_dir / "edge_stats.csv")
    write_graphml(graph, output_dir / "graph.graphml")

    summary = {"build_report": build_report.to_dict(), **analysis}
    (output_dir / "graph_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    sample = select_top_attack_edges(graph, n=30)
    if sample.number_of_nodes() > 0:
        draw_graph(sample, output_dir / "visualizations" / "top_attack_edges.png", title="Top 30 Attack-Related Edges")

    return graph, build_report, summary


def main() -> None:
    graph, build_report, summary = run()
    print(f"Files processed: {build_report.files_processed}")
    print(f"Total raw rows: {build_report.total_raw_rows:,}")
    print(f"Blank rows dropped: {build_report.total_blank_rows:,}")
    print(f"Real flows in graph: {build_report.total_real_flows:,}")
    print(f"Nodes: {build_report.node_count:,}  Edges: {build_report.edge_count:,}")
    print(f"Runtime: {build_report.runtime_seconds:.2f}s")
    print(f"Peak memory: {build_report.peak_memory_mb} MB")
    print(f"Artifacts written under: {GRAPH_OUTPUT_DIR}")


if __name__ == "__main__":
    main()
