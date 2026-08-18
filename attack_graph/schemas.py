"""Graph schema: required raw columns, label/protocol handling, and the
mutable accumulators used to aggregate repeated flows into single edges
before any NetworkX object is built.

Node schema (final graph node attributes):
    ip                       str, the node identity
    total_flow_count         int, flows where this node is source or destination
                              (see docstring on NodeAccumulator for the
                              self-loop double-count caveat)
    benign_flow_count        int
    attack_flow_count        int
    attack_ratio             float, attack_flow_count / total_flow_count
    in_degree                int, set by attack_graph.analysis.graph_metrics
    out_degree                int, set by attack_graph.analysis.graph_metrics
    degree                   int, in_degree + out_degree
    unique_source_count      int, == in_degree by construction (edges are
                              aggregated per unique (src, dst) pair, so each
                              distinct predecessor contributes exactly one
                              inbound edge)
    unique_destination_count int, == out_degree, same reasoning

Edge schema (final graph edge attributes, one edge per unique (src_ip, dst_ip)
pair -- see EdgeAccumulator.to_edge_attributes):
    flow_count                int
    benign_flow_count         int
    attack_flow_count         int
    attack_ratio              float
    unique_source_ports       int (count, not the raw set -- kept compact)
    unique_destination_ports  int
    protocols_seen            list[int], subset of PROTOCOL_NAMES keys
    first_seen / last_seen    str, ISO 8601, or null if no timestamps parsed
    total_forward_bytes       int, sum of "Total Length of Fwd Packets"
    total_backward_bytes      int, sum of "Total Length of Bwd Packets"
    attack_labels             list[str], canonical attack categories seen on
                               this edge (BENIGN excluded)

This is a communication/topology graph annotated with observed traffic
statistics -- none of these fields are risk scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

# Only these raw columns are read from ml/datasets/raw_labelled_flows/ CSVs
# (matched after stripping whitespace from the real header names). The
# other ~75 CICFlowMeter statistical columns aren't needed for topology and
# are skipped at read time to bound memory use on multi-hundred-MB files.
REQUIRED_RAW_COLUMNS: list[str] = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Label",
]

# Verified against every file in ml/datasets/raw_labelled_flows/
# (docs/dataset_inspection_labelled_flows.md, 2026-08-18): exactly these
# three protocol numbers occur in the real dataset. Used only for a
# human-readable name; the numeric field itself is always preserved as-is.
PROTOCOL_NAMES: dict[int, str] = {6: "TCP", 17: "UDP", 0: "OTHER"}

BENIGN_LABEL = "BENIGN"
ATTACK_LABEL = "ATTACK"


def traffic_class(canonical_label: str) -> str:
    """Binary BENIGN/ATTACK classification derived from canonical_label.

    Documented mapping: canonical_label == "BENIGN" -> "BENIGN"; every other
    canonical_label (DDoS, PortScan, Bot, Infiltration, FTP-Patator,
    SSH-Patator, DoS Hulk/GoldenEye/slowloris/Slowhttptest, Heartbleed,
    Web Attack - Brute Force/XSS/Sql Injection) -> "ATTACK". This collapses
    attack subtype into a coarse binary for aggregate stats only -- the
    specific canonical_label is preserved separately (see attack_labels on
    EdgeAccumulator) and is never discarded.
    """
    return BENIGN_LABEL if canonical_label == BENIGN_LABEL else ATTACK_LABEL


@dataclass
class CleaningStats:
    """Row-level accounting for one cleaning pass, so blank/invalid rows are
    reported rather than silently dropped."""

    raw_rows: int = 0
    blank_rows: int = 0
    invalid_ip_rows: int = 0
    invalid_port_rows: int = 0
    invalid_timestamp_rows: int = 0
    valid_rows: int = 0

    def __add__(self, other: "CleaningStats") -> "CleaningStats":
        return CleaningStats(
            raw_rows=self.raw_rows + other.raw_rows,
            blank_rows=self.blank_rows + other.blank_rows,
            invalid_ip_rows=self.invalid_ip_rows + other.invalid_ip_rows,
            invalid_port_rows=self.invalid_port_rows + other.invalid_port_rows,
            invalid_timestamp_rows=self.invalid_timestamp_rows + other.invalid_timestamp_rows,
            valid_rows=self.valid_rows + other.valid_rows,
        )

    def to_dict(self) -> dict:
        return {
            "raw_rows": self.raw_rows,
            "blank_rows": self.blank_rows,
            "invalid_ip_rows": self.invalid_ip_rows,
            "invalid_port_rows": self.invalid_port_rows,
            "invalid_timestamp_rows": self.invalid_timestamp_rows,
            "valid_rows": self.valid_rows,
        }


@dataclass
class EdgeAccumulator:
    """Mutable running aggregate for one (src_ip, dst_ip) pair while scanning
    CSV chunks. Never itself added to a NetworkX graph -- converted to a
    plain, JSON/GraphML-safe attribute dict by to_edge_attributes() once
    accumulation across all files is complete."""

    flow_count: int = 0
    benign_flow_count: int = 0
    attack_flow_count: int = 0
    src_ports: set[int] = field(default_factory=set)
    dst_ports: set[int] = field(default_factory=set)
    protocols: set[int] = field(default_factory=set)
    first_seen: pd.Timestamp | None = None
    last_seen: pd.Timestamp | None = None
    total_forward_bytes: int = 0
    total_backward_bytes: int = 0
    attack_labels: set[str] = field(default_factory=set)

    def observe(
        self,
        *,
        canonical_label: str,
        src_port: int,
        dst_port: int,
        protocol: int,
        timestamp: pd.Timestamp | None,
        fwd_bytes: float,
        bwd_bytes: float,
    ) -> None:
        self.flow_count += 1
        if canonical_label == BENIGN_LABEL:
            self.benign_flow_count += 1
        else:
            self.attack_flow_count += 1
            self.attack_labels.add(canonical_label)
        self.src_ports.add(int(src_port))
        self.dst_ports.add(int(dst_port))
        self.protocols.add(int(protocol))
        if timestamp is not None and not pd.isna(timestamp):
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp
        self.total_forward_bytes += int(fwd_bytes)
        self.total_backward_bytes += int(bwd_bytes)

    def attack_ratio(self) -> float:
        return self.attack_flow_count / self.flow_count if self.flow_count else 0.0

    def to_edge_attributes(self) -> dict:
        return {
            "flow_count": self.flow_count,
            "benign_flow_count": self.benign_flow_count,
            "attack_flow_count": self.attack_flow_count,
            "attack_ratio": round(self.attack_ratio(), 6),
            "unique_source_ports": len(self.src_ports),
            "unique_destination_ports": len(self.dst_ports),
            "protocols_seen": sorted(self.protocols),
            "first_seen": self.first_seen.isoformat() if self.first_seen is not None else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen is not None else None,
            "total_forward_bytes": self.total_forward_bytes,
            "total_backward_bytes": self.total_backward_bytes,
            "attack_labels": sorted(self.attack_labels),
        }


@dataclass
class NodeAccumulator:
    """Mutable running aggregate for one IP, derived from EdgeAccumulators
    after all edges are known (a node's stats depend on every edge it
    touches as either source or destination).

    Caveat (documented, not a bug): if src_ip == dst_ip (a self-loop) ever
    occurs, those flows are counted once as outgoing and once as incoming,
    so total_flow_count double-counts self-loop flows. Verified not to
    occur in the real dataset (see performance-run report); flagged here in
    case future data introduces it.
    """

    total_flow_count: int = 0
    benign_flow_count: int = 0
    attack_flow_count: int = 0

    def attack_ratio(self) -> float:
        return self.attack_flow_count / self.total_flow_count if self.total_flow_count else 0.0

    def to_node_attributes(self, ip: str) -> dict:
        return {
            "ip": ip,
            "total_flow_count": self.total_flow_count,
            "benign_flow_count": self.benign_flow_count,
            "attack_flow_count": self.attack_flow_count,
            "attack_ratio": round(self.attack_ratio(), 6),
        }
