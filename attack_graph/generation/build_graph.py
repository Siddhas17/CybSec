"""Aggregation and NetworkX graph construction.

Pipeline (see docs/attack_graph.md "Scalability considerations"):

    CSV chunks -> drop blank rows -> validate/parse fields -> normalize
    labels -> aggregate source->destination statistics -> build compact
    NetworkX graph

Aggregation happens in plain-Python dict accumulators
(attack_graph.schemas.EdgeAccumulator / NodeAccumulator) *before* any
NetworkX object exists, so memory scales with the number of unique
(src_ip, dst_ip) pairs -- verified to be orders of magnitude smaller than
the raw flow count on the real dataset -- not with the number of raw flow
records.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import pandas as pd

try:
    import resource

    def _peak_memory_mb() -> float | None:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
except ImportError:  # resource is POSIX-only; this project runs in WSL2 (see README.md)
    def _peak_memory_mb() -> float | None:
        return None

from attack_graph.config import DEFAULT_CHUNK_SIZE, TOPOLOGY_RAW_DIR
from attack_graph.generation.cleaner import clean_chunk
from attack_graph.generation.loader import discover_csv_files, iter_topology_chunks
from attack_graph.schemas import CleaningStats, EdgeAccumulator, NodeAccumulator

_RENAME_FOR_ITERATION = {
    "Source IP": "src_ip",
    "Destination IP": "dst_ip",
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
}


@dataclass
class FileReport:
    filename: str
    raw_rows: int
    blank_rows: int
    invalid_ip_rows: int
    invalid_port_rows: int
    invalid_timestamp_rows: int
    valid_rows: int


@dataclass
class BuildReport:
    files_processed: int = 0
    total_raw_rows: int = 0
    total_blank_rows: int = 0
    total_invalid_ip_rows: int = 0
    total_invalid_port_rows: int = 0
    total_invalid_timestamp_rows: int = 0
    total_valid_rows: int = 0
    total_real_flows: int = 0
    node_count: int = 0
    edge_count: int = 0
    runtime_seconds: float = 0.0
    peak_memory_mb: float | None = None
    time_window: tuple[str, str] | None = None
    per_file: list[FileReport] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files_processed": self.files_processed,
            "total_raw_rows": self.total_raw_rows,
            "total_blank_rows": self.total_blank_rows,
            "total_invalid_ip_rows": self.total_invalid_ip_rows,
            "total_invalid_port_rows": self.total_invalid_port_rows,
            "total_invalid_timestamp_rows": self.total_invalid_timestamp_rows,
            "total_valid_rows": self.total_valid_rows,
            "total_real_flows": self.total_real_flows,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "runtime_seconds": round(self.runtime_seconds, 3),
            "peak_memory_mb": round(self.peak_memory_mb, 1) if self.peak_memory_mb else None,
            "time_window": self.time_window,
            "per_file": [vars(f) for f in self.per_file],
        }


def _within_window(ts: pd.Series, window: tuple[pd.Timestamp, pd.Timestamp]) -> pd.Series:
    start, end = window
    return (ts >= start) & (ts <= end)


def hourly_windows(
    start: pd.Timestamp, end: pd.Timestamp
) -> Iterator[tuple[pd.Timestamp, pd.Timestamp]]:
    """Yield consecutive 1-hour [start, end) windows covering [start, end].

    A caller gets an hourly view by calling build_graph_from_directory once
    per window (time_window=window) -- this module deliberately does not
    maintain multiple graphs itself, per the instruction not to overbuild
    temporal support in this phase.
    """
    current = start
    step = pd.Timedelta(hours=1)
    while current < end:
        window_end = min(current + step, end)
        yield current, window_end
        current = window_end


def build_graph_from_directory(
    raw_dir: Path = TOPOLOGY_RAW_DIR,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    time_window: tuple[pd.Timestamp, pd.Timestamp] | None = None,
    files: list[Path] | None = None,
) -> tuple[nx.DiGraph, BuildReport]:
    """Build the aggregated attack-communication graph.

    `time_window`, if given, restricts included flows to those whose parsed
    Timestamp falls within [start, end) -- the user-configured time-window
    aggregation mode. Omit it (default) for the global graph.
    """
    start_time = time.monotonic()
    csv_files = files if files is not None else discover_csv_files(raw_dir)

    edges: dict[tuple[str, str], EdgeAccumulator] = {}
    report = BuildReport(
        time_window=(time_window[0].isoformat(), time_window[1].isoformat()) if time_window else None
    )

    for csv_path in csv_files:
        file_stats = CleaningStats()
        for raw_chunk in iter_topology_chunks(csv_path, chunk_size):
            clean, chunk_stats = clean_chunk(raw_chunk)
            file_stats = file_stats + chunk_stats

            if time_window is not None:
                clean = clean.loc[_within_window(clean["Timestamp"], time_window)]
            if clean.empty:
                continue

            renamed = clean.rename(columns=_RENAME_FOR_ITERATION)
            for row in renamed.itertuples(index=False):
                key = (row.src_ip, row.dst_ip)
                acc = edges.get(key)
                if acc is None:
                    acc = EdgeAccumulator()
                    edges[key] = acc
                acc.observe(
                    canonical_label=row.canonical_label,
                    src_port=row.src_port,
                    dst_port=row.dst_port,
                    protocol=row.protocol,
                    timestamp=row.timestamp,
                    fwd_bytes=row.fwd_bytes,
                    bwd_bytes=row.bwd_bytes,
                )

        report.per_file.append(FileReport(filename=csv_path.name, **file_stats.to_dict()))
        report.files_processed += 1
        report.total_raw_rows += file_stats.raw_rows
        report.total_blank_rows += file_stats.blank_rows
        report.total_invalid_ip_rows += file_stats.invalid_ip_rows
        report.total_invalid_port_rows += file_stats.invalid_port_rows
        report.total_invalid_timestamp_rows += file_stats.invalid_timestamp_rows
        report.total_valid_rows += file_stats.valid_rows

    nodes: dict[str, NodeAccumulator] = {}
    for (src_ip, dst_ip), edge_acc in edges.items():
        for ip in (src_ip, dst_ip):
            node_acc = nodes.get(ip)
            if node_acc is None:
                node_acc = NodeAccumulator()
                nodes[ip] = node_acc
            node_acc.total_flow_count += edge_acc.flow_count
            node_acc.benign_flow_count += edge_acc.benign_flow_count
            node_acc.attack_flow_count += edge_acc.attack_flow_count

    graph = nx.DiGraph()
    for ip, node_acc in nodes.items():
        graph.add_node(ip, **node_acc.to_node_attributes(ip))
    for (src_ip, dst_ip), edge_acc in edges.items():
        graph.add_edge(src_ip, dst_ip, **edge_acc.to_edge_attributes())

    report.node_count = graph.number_of_nodes()
    report.edge_count = graph.number_of_edges()
    report.total_real_flows = sum(acc.flow_count for acc in edges.values())
    report.runtime_seconds = time.monotonic() - start_time
    report.peak_memory_mb = _peak_memory_mb()

    return graph, report
