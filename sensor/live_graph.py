"""LIVE_GRAPH: a bounded, in-memory, incremental communication graph built
only from observed live TelemetryEvents (section 8/9).

This is explicitly NOT the Phase 2 attack graph (OFFLINE_GRAPH,
attack_graph/, persisted in MySQL by backend/app/services/graph_service.py
and built once from the full labeled CICIDS2017 dataset). The two are
never merged into one object and a DetectionResult always records which
one produced its graph context (backend/app/services/live_sensor_service.py
sets graph_source="live_graph"; offline/test paths already use
graph_source="offline_graph" implicitly, see docs/live_telemetry.md
section 7) -- section 8 explicitly forbids presenting the offline
retrospective graph as real-time context, and the reverse mistake (letting
a young live graph's thin edge history read as confidently as the
label-informed offline graph) is avoided the same way: LIVE_GRAPH's
"attack ratio" is a fraction of *this edge's own live detections the
analytical pipeline itself flagged*, never ground truth -- there is none
for genuinely live traffic (section 9's explicit warning).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class LiveGraphContext:
    edge_attack_ratio: float | None = None
    edge_attack_flow_count: int | None = None
    edge_flow_count: int | None = None
    edge_first_seen: str | None = None
    edge_last_seen: str | None = None
    edge_attack_label_count: int | None = None  # always 0 here -- live traffic has no ground-truth label history

    def is_empty(self) -> bool:
        return self.edge_flow_count is None


@dataclass
class _LiveEdgeStats:
    flow_count: int = 0
    flagged_flow_count: int = 0
    unique_source_ports: set[int] = field(default_factory=set)
    unique_destination_ports: set[int] = field(default_factory=set)
    protocols_seen: set[int] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0


class LiveGraph:
    """Configurable retention controls (section 9): edges idle longer than
    `window_seconds` are evicted on cleanup(); if the edge count still
    exceeds `max_edges`, the least-recently-active edges are evicted next.
    Thread-safe -- record_flow()/cleanup() are called from the sensor
    ingestion loop, get_context() from request-handling code."""

    def __init__(self, window_seconds: float, max_edges: int) -> None:
        self._window_seconds = window_seconds
        self._max_edges = max_edges
        self._edges: dict[tuple[str, str], _LiveEdgeStats] = {}
        self._lock = threading.Lock()

    def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int | None,
        dst_port: int | None,
        protocol: int,
        timestamp: float,
        is_flagged: bool,
    ) -> None:
        with self._lock:
            key = (src_ip, dst_ip)
            stats = self._edges.get(key)
            if stats is None:
                stats = _LiveEdgeStats(first_seen=timestamp, last_seen=timestamp)
                self._edges[key] = stats
            stats.flow_count += 1
            if is_flagged:
                stats.flagged_flow_count += 1
            if src_port is not None:
                stats.unique_source_ports.add(src_port)
            if dst_port is not None:
                stats.unique_destination_ports.add(dst_port)
            stats.protocols_seen.add(protocol)
            stats.first_seen = min(stats.first_seen, timestamp)
            stats.last_seen = max(stats.last_seen, timestamp)
            self._enforce_max_edges_locked()

    def get_context(self, src_ip: str, dst_ip: str) -> LiveGraphContext:
        with self._lock:
            stats = self._edges.get((src_ip, dst_ip))
            if stats is None:
                return LiveGraphContext()
            ratio = stats.flagged_flow_count / stats.flow_count if stats.flow_count else 0.0
            return LiveGraphContext(
                edge_attack_ratio=ratio,
                edge_attack_flow_count=stats.flagged_flow_count,
                edge_flow_count=stats.flow_count,
                edge_first_seen=datetime.fromtimestamp(stats.first_seen, tz=UTC).isoformat(),
                edge_last_seen=datetime.fromtimestamp(stats.last_seen, tz=UTC).isoformat(),
                edge_attack_label_count=0,
            )

    def cleanup(self, now_ts: float) -> int:
        """TTL eviction (section 9). Returns the number of edges removed."""
        with self._lock:
            expired = [k for k, s in self._edges.items() if (now_ts - s.last_seen) > self._window_seconds]
            for k in expired:
                del self._edges[k]
            return len(expired)

    def _enforce_max_edges_locked(self) -> None:
        if len(self._edges) <= self._max_edges:
            return
        overflow = len(self._edges) - self._max_edges
        oldest = sorted(self._edges.items(), key=lambda kv: kv[1].last_seen)[:overflow]
        for k, _ in oldest:
            del self._edges[k]

    @property
    def edge_count(self) -> int:
        with self._lock:
            return len(self._edges)
