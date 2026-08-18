"""Tests for risk_engine.data_bridge: graph-context attachment and scale
derivation against tiny synthetic graphs, plus one true end-to-end
integration test (synthetic CSV -> cleaning -> feature extraction ->
scoring -> graph join) using a tiny synthetic autoencoder -- never the
real trained model or the real dataset.
"""

import json
import pickle

import networkx as nx
import pandas as pd
import pytest
import torch
from sklearn.preprocessing import StandardScaler

from ml.models.autoencoder import Autoencoder, AutoencoderConfig
from ml.models.inference import AutoencoderPredictor
from risk_engine.data_bridge import FEATURE_NAMES, attach_graph_context, derive_scale_parameters


@pytest.fixture
def sample_graph():
    g = nx.DiGraph()
    g.add_edge(
        "1.1.1.1", "2.2.2.2",
        attack_ratio=0.5, attack_flow_count=10, flow_count=20,
        first_seen="2017-07-03T00:00:00", last_seen="2017-07-03T10:00:00",
        attack_labels=["DDoS"],
    )
    g.add_edge(
        "2.2.2.2", "3.3.3.3",
        attack_ratio=1.0, attack_flow_count=100, flow_count=100,
        first_seen="2017-07-03T00:00:00", last_seen="2017-07-04T00:00:00",
        attack_labels=["PortScan", "Bot"],
    )
    return g


def test_attach_graph_context_matches_known_edges(sample_graph):
    joint_df = pd.DataFrame(
        {
            "src_ip": ["1.1.1.1", "2.2.2.2", "9.9.9.9"],
            "dst_ip": ["2.2.2.2", "3.3.3.3", "8.8.8.8"],
            "anomaly_score": [0.1, 0.2, 0.3],
        }
    )
    result = attach_graph_context(joint_df, sample_graph)

    assert result.loc[0, "edge_attack_ratio"] == 0.5
    assert result.loc[0, "edge_attack_flow_count"] == 10
    assert result.loc[1, "edge_attack_label_count"] == 2
    # unmatched pair (9.9.9.9 -> 8.8.8.8) gets NaN, not a crash
    assert pd.isna(result.loc[2, "edge_attack_ratio"])


def test_derive_scale_parameters_from_known_graph(sample_graph):
    scales = derive_scale_parameters(sample_graph)
    assert scales["attack_activity_scale"] > 0
    assert scales["temporal_scale_hours"] > 0
    assert scales["derivation"]["edges_used_for_activity_scale"] == 2
    assert scales["derivation"]["edges_used_for_temporal_scale"] == 2


def test_derive_scale_parameters_handles_empty_graph():
    empty = nx.DiGraph()
    scales = derive_scale_parameters(empty)
    assert scales["attack_activity_scale"] > 0  # falls back to a documented default, doesn't crash
    assert scales["temporal_scale_hours"] > 0


def _write_tiny_autoencoder_artifact(tmp_path, feature_names):
    n = len(feature_names)
    config = AutoencoderConfig(dims=[n, max(2, n // 2)])
    model = Autoencoder(config)
    torch.save(model.state_dict(), tmp_path / "best_model.pt")

    rng = __import__("numpy").random.default_rng(0)
    scaler = StandardScaler().fit(rng.normal(size=(50, n)))
    with open(tmp_path / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    (tmp_path / "config.json").write_text(json.dumps({"architecture": config.to_dict()}), encoding="utf-8")
    (tmp_path / "feature_names.json").write_text(json.dumps(feature_names), encoding="utf-8")
    (tmp_path / "threshold.json").write_text(json.dumps({"selected_threshold": 0.5}), encoding="utf-8")


def test_build_joint_flow_dataset_end_to_end(tmp_path, monkeypatch):
    # Use the real FEATURE_NAMES (loaded from the trained artifact at
    # import time) so the synthetic CSV's columns line up with what
    # data_bridge actually selects -- but score with a tiny synthetic
    # model/scaler, not the real trained one.
    feature_names = FEATURE_NAMES
    artifact_dir = tmp_path / "artifact"
    artifact_dir.mkdir()
    _write_tiny_autoencoder_artifact(artifact_dir, feature_names)
    predictor = AutoencoderPredictor.load(artifact_dir)

    raw_dir = tmp_path / "raw_labelled_flows"
    raw_dir.mkdir()

    topology_cols = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"]
    all_cols = topology_cols + [c for c in feature_names if c not in topology_cols]

    rows = []
    for i in range(4):
        row = {c: 1.0 for c in all_cols}
        row.update(
            {
                "Flow ID": f"flow-{i}",
                "Source IP": "1.1.1.1",
                "Source Port": 1000 + i,
                "Destination IP": "2.2.2.2",
                "Destination Port": 80,
                "Protocol": 6,
                "Timestamp": "3/7/2017 08:00",
                "Label": "BENIGN" if i % 2 == 0 else "DDoS",
            }
        )
        rows.append(row)
    df = pd.DataFrame(rows, columns=all_cols)
    df.to_csv(raw_dir / "sample.pcap_ISCX.csv", index=False)

    from risk_engine.data_bridge import build_joint_flow_dataset

    joint_df, report = build_joint_flow_dataset(raw_dir, predictor, chunk_size=100)

    assert report["total_raw_rows"] == 4
    assert report["total_scored_rows"] == 4
    assert len(joint_df) == 4
    assert set(joint_df["src_ip"]) == {"1.1.1.1"}
    assert set(joint_df["canonical_label"]) == {"BENIGN", "DDoS"}
    assert "anomaly_score" in joint_df.columns
    assert (joint_df["anomaly_score"] >= 0).all()
