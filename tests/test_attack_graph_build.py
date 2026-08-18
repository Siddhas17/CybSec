"""Integration test: small synthetic CSV -> cleaning -> aggregation ->
NetworkX graph, covering repeated-edge aggregation, node/edge metrics,
attack ratio, first_seen/last_seen, attack-label aggregation, deterministic
output, and time-window filtering.
"""

import pandas as pd
import pytest

from attack_graph.generation.build_graph import build_graph_from_directory, hourly_windows

HEADER = (
    "Flow ID, Source IP, Source Port, Destination IP, Destination Port, "
    "Protocol, Timestamp,Total Length of Fwd Packets, Total Length of Bwd Packets, Label"
)

ROWS = [
    # A -> B, three flows: two BENIGN, one DDoS attack (different ports/protocols)
    "f1,1.1.1.1,100,2.2.2.2,80,6,3/7/2017 08:00,10,5,BENIGN",
    "f2,1.1.1.1,101,2.2.2.2,80,6,3/7/2017 09:00,20,10,BENIGN",
    "f3,1.1.1.1,102,2.2.2.2,81,17,3/7/2017 07:00,5,2,DDoS",
    # B -> C, one PortScan attack flow
    "f4,2.2.2.2,200,3.3.3.3,22,6,3/7/2017 10:00,1,1,PortScan",
]

BLANK_ROW = "" + "," * 9  # 10 empty fields matching the header's column count


@pytest.fixture
def synthetic_dir(tmp_path):
    raw_dir = tmp_path / "raw_labelled_flows"
    raw_dir.mkdir()
    content = HEADER + "\n" + "\n".join(ROWS) + "\n" + BLANK_ROW + "\n"
    (raw_dir / "sample.pcap_ISCX.csv").write_text(content, encoding="utf-8")
    return raw_dir


def test_build_graph_structure_and_repeated_edge_aggregation(synthetic_dir):
    graph, report = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)

    assert set(graph.nodes) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert set(graph.edges) == {("1.1.1.1", "2.2.2.2"), ("2.2.2.2", "3.3.3.3")}
    assert graph.number_of_edges() == 2  # 3 A->B flows collapsed into 1 edge


def test_build_graph_reports_blank_row_and_flow_counts(synthetic_dir):
    _, report = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)

    assert report.total_raw_rows == 5
    assert report.total_blank_rows == 1
    assert report.total_valid_rows == 4
    assert report.total_real_flows == 4
    assert report.node_count == 3
    assert report.edge_count == 2


def test_edge_metrics_aggregate_correctly(synthetic_dir):
    graph, _ = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)
    ab = graph.edges["1.1.1.1", "2.2.2.2"]

    assert ab["flow_count"] == 3
    assert ab["benign_flow_count"] == 2
    assert ab["attack_flow_count"] == 1
    assert ab["attack_ratio"] == pytest.approx(1 / 3)
    assert ab["unique_source_ports"] == 3
    assert ab["unique_destination_ports"] == 2
    assert ab["protocols_seen"] == [6, 17]
    assert ab["attack_labels"] == ["DDoS"]
    assert ab["total_forward_bytes"] == 35
    assert ab["total_backward_bytes"] == 17


def test_edge_first_seen_last_seen_use_min_max_not_row_order(synthetic_dir):
    graph, _ = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)
    ab = graph.edges["1.1.1.1", "2.2.2.2"]

    # f3 (07:00) is the earliest timestamp despite appearing last in the file;
    # f2 (09:00) is the latest despite appearing before f3.
    assert ab["first_seen"].startswith("2017-07-03T07:00")
    assert ab["last_seen"].startswith("2017-07-03T09:00")


def test_node_metrics_sum_across_incident_edges(synthetic_dir):
    graph, _ = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)

    a = graph.nodes["1.1.1.1"]
    assert a["total_flow_count"] == 3
    assert a["benign_flow_count"] == 2
    assert a["attack_flow_count"] == 1

    # B is destination for 3 A->B flows and source for 1 B->C flow
    b = graph.nodes["2.2.2.2"]
    assert b["total_flow_count"] == 4
    assert b["benign_flow_count"] == 2
    assert b["attack_flow_count"] == 2
    assert b["attack_ratio"] == pytest.approx(0.5)

    c = graph.nodes["3.3.3.3"]
    assert c["total_flow_count"] == 1
    assert c["attack_flow_count"] == 1


def test_build_graph_is_deterministic(synthetic_dir):
    graph1, report1 = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)
    graph2, report2 = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100)

    assert sorted(graph1.nodes(data=True)) == sorted(graph2.nodes(data=True))
    assert sorted(graph1.edges(data=True)) == sorted(graph2.edges(data=True))

    # Exclude fields that legitimately vary run-to-run (wall-clock timing,
    # and memory readings that can be volatile in a virtualized/WSL2 host).
    d1, d2 = report1.to_dict(), report2.to_dict()
    for volatile_field in ("runtime_seconds", "peak_memory_mb"):
        d1.pop(volatile_field)
        d2.pop(volatile_field)
    assert d1 == d2


def test_time_window_filters_flows(synthetic_dir):
    window = (pd.Timestamp("2017-07-03 08:30"), pd.Timestamp("2017-07-03 10:30"))
    graph, report = build_graph_from_directory(raw_dir=synthetic_dir, chunk_size=100, time_window=window)

    # Only f2 (09:00, A->B) and f4 (10:00, B->C) fall inside the window;
    # f1 (08:00) and f3 (07:00) are excluded.
    assert report.total_real_flows == 2
    ab = graph.edges["1.1.1.1", "2.2.2.2"]
    assert ab["flow_count"] == 1
    assert ab["benign_flow_count"] == 1
    assert ab["attack_flow_count"] == 0


def test_hourly_windows_covers_full_range_without_gaps():
    start = pd.Timestamp("2017-07-03 00:00")
    end = pd.Timestamp("2017-07-03 02:30")
    windows = list(hourly_windows(start, end))

    assert windows[0] == (pd.Timestamp("2017-07-03 00:00"), pd.Timestamp("2017-07-03 01:00"))
    assert windows[-1][1] == end
    for (a_start, a_end), (b_start, b_end) in zip(windows, windows[1:]):
        assert a_end == b_start
