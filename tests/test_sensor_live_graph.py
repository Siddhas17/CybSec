"""Section 16 unit tests: LiveGraph's TTL/eviction/context logic, entirely
in-memory -- never real network traffic (see sensor/live_graph.py and
docs/live_telemetry.md section 9 for what this bounded, non-ground-truth
graph is and is not)."""

from __future__ import annotations

from sensor.live_graph import LiveGraph

SRC, DST = "10.0.0.1", "10.0.0.2"


def test_unknown_edge_returns_empty_context():
    graph = LiveGraph(window_seconds=3600, max_edges=100)
    context = graph.get_context(SRC, DST)
    assert context.is_empty()
    assert context.edge_attack_ratio is None


def test_record_flow_accumulates_counts_and_attack_ratio():
    graph = LiveGraph(window_seconds=3600, max_edges=100)
    graph.record_flow(SRC, DST, 5000, 443, 6, timestamp=1.0, is_flagged=False)
    graph.record_flow(SRC, DST, 5001, 443, 6, timestamp=2.0, is_flagged=True)
    graph.record_flow(SRC, DST, 5002, 443, 6, timestamp=3.0, is_flagged=True)

    context = graph.get_context(SRC, DST)
    assert not context.is_empty()
    assert context.edge_flow_count == 3
    assert context.edge_attack_flow_count == 2
    assert context.edge_attack_ratio == 2 / 3
    # Never ground truth for live traffic (section 9) -- always 0, unlike OFFLINE_GRAPH.
    assert context.edge_attack_label_count == 0
    assert graph.edge_count == 1


def test_reverse_direction_is_a_distinct_edge():
    graph = LiveGraph(window_seconds=3600, max_edges=100)
    graph.record_flow(SRC, DST, 5000, 443, 6, timestamp=1.0, is_flagged=False)
    assert graph.get_context(DST, SRC).is_empty()
    assert not graph.get_context(SRC, DST).is_empty()


def test_cleanup_evicts_edges_idle_longer_than_window():
    graph = LiveGraph(window_seconds=10.0, max_edges=100)
    graph.record_flow(SRC, DST, 5000, 443, 6, timestamp=0.0, is_flagged=False)

    removed = graph.cleanup(now_ts=5.0)
    assert removed == 0
    assert graph.edge_count == 1

    removed = graph.cleanup(now_ts=15.0)
    assert removed == 1
    assert graph.edge_count == 0
    assert graph.get_context(SRC, DST).is_empty()


def test_max_edges_evicts_least_recently_active_edge_first():
    graph = LiveGraph(window_seconds=3600, max_edges=2)
    graph.record_flow(SRC, "10.0.0.10", 1, 1, 17, timestamp=1.0, is_flagged=False)
    graph.record_flow(SRC, "10.0.0.11", 1, 1, 17, timestamp=2.0, is_flagged=False)
    assert graph.edge_count == 2

    # A third distinct edge pushes the count over max_edges -- the oldest
    # (10.0.0.10, last_seen=1.0) must be evicted, not the newest.
    graph.record_flow(SRC, "10.0.0.12", 1, 1, 17, timestamp=3.0, is_flagged=False)
    assert graph.edge_count == 2
    assert graph.get_context(SRC, "10.0.0.10").is_empty()
    assert not graph.get_context(SRC, "10.0.0.11").is_empty()
    assert not graph.get_context(SRC, "10.0.0.12").is_empty()
