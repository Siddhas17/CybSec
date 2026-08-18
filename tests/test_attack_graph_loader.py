"""Verifies the chunked loader selects only the required topology columns
and strips whitespace from their names, using a small synthetic CSV that
reproduces the real files' leading-space header quirk."""

import pandas as pd

from attack_graph.generation.loader import discover_csv_files, iter_topology_chunks
from attack_graph.schemas import REQUIRED_RAW_COLUMNS


def _write_synthetic_csv(tmp_path, name="sample.csv"):
    # Mirrors the real header: "Flow ID" has no leading space, most others do.
    header = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp,Total Length of Fwd Packets, Total Length of Bwd Packets, Extra Feature Column, Label"
    rows = [
        "a-b-1-2-6,192.168.10.5,443,104.16.28.216,80,6,3/7/2017 08:55,12,6,999,BENIGN",
        "c-d-3-4-6,192.168.10.5,444,104.16.28.216,80,6,3/7/2017 08:56,20,10,111,DDoS",
    ]
    path = tmp_path / name
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def test_iter_topology_chunks_selects_and_strips_required_columns(tmp_path):
    path = _write_synthetic_csv(tmp_path)
    chunks = list(iter_topology_chunks(path, chunk_size=10))

    assert len(chunks) == 1
    df = chunks[0]
    assert set(df.columns) == set(REQUIRED_RAW_COLUMNS)
    assert "Extra Feature Column" not in df.columns
    assert len(df) == 2
    assert df.iloc[0]["Source IP"] == "192.168.10.5"


def test_iter_topology_chunks_respects_chunk_size(tmp_path):
    path = _write_synthetic_csv(tmp_path)
    chunks = list(iter_topology_chunks(path, chunk_size=1))
    assert len(chunks) == 2
    assert all(len(c) == 1 for c in chunks)


def test_discover_csv_files_sorted(tmp_path):
    _write_synthetic_csv(tmp_path, "b.csv")
    _write_synthetic_csv(tmp_path, "a.csv")
    files = discover_csv_files(tmp_path)
    assert [f.name for f in files] == ["a.csv", "b.csv"]
