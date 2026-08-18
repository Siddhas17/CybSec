"""Joins the two independently-generated Phase 2/Phase 3 systems into a
per-flow dataset carrying BOTH a real anomaly score and real attack-graph
edge context -- neither system alone can produce this.

**Why this bridge is necessary (documented, not hidden):** the Phase 3
autoencoder was trained on `ml/datasets/raw/` (the `MachineLearningCSV`
distribution -- no Source/Destination IP at all, see
`docs/cleaning_pipeline_cicids2017.md`), while the Phase 2 attack graph
was built from `ml/datasets/raw_labelled_flows/` (`GeneratedLabelledFlows`
-- has IPs, but is a *different* CSV export of the same underlying
captures, with no shared row-level join key such as a common Flow ID).
There is no way to look up "this exact Phase 1 test-split row's edge in
the Phase 2 graph."

**Resolution used here:** `raw_labelled_flows/` contains the identical 67
model-feature columns (verified byte-for-byte by name against
`ml/datasets/processed/feature_names.json`) *plus* the topology fields.
This module re-derives the 67-feature vector for each `raw_labelled_flows`
row, applies the *same persisted* Phase 1 scaler and Phase 3 model (loaded
via `ml.models.inference.AutoencoderPredictor`, never refit/retrained --
see the Phase 3 leakage checks this reuses), and joins the resulting
anomaly score with that same row's Source/Destination IP -- giving one
flow both signals honestly, at the cost of not being literally Phase
1/3's original train/val/test partition.

**Documented limitation:** because this necessarily draws on the same
underlying captures the autoencoder was trained on, flows scored here are
NOT guaranteed to be a strictly independent held-out set relative to
Phase 3's training data -- some scored flows may correspond to flows that
contributed to autoencoder training. The autoencoder's weights and
threshold are never changed by anything in this module (both are loaded
read-only from the Phase 3 artifact directory). See
docs/risk_engine.md "Data bridge and its limitations" for the full
disclosure.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd

from attack_graph.generation.cleaner import clean_chunk
from attack_graph.generation.loader import _detect_encoding, discover_csv_files
from attack_graph.schemas import REQUIRED_RAW_COLUMNS as TOPOLOGY_COLUMNS
from ml.models.inference import AutoencoderPredictor
from ml.training.train_autoencoder import ARTIFACT_DIR as AUTOENCODER_ARTIFACT_DIR

FEATURE_NAMES: list[str] = json.loads((AUTOENCODER_ARTIFACT_DIR / "feature_names.json").read_text())
_NEEDED_COLUMNS = sorted(set(FEATURE_NAMES) | set(TOPOLOGY_COLUMNS))


def _select_column(name: str) -> bool:
    return name.strip() in _NEEDED_COLUMNS


def _iter_joint_chunks(csv_path: Path, chunk_size: int) -> Iterator[pd.DataFrame]:
    encoding = _detect_encoding(csv_path)
    reader = pd.read_csv(csv_path, usecols=_select_column, chunksize=chunk_size, low_memory=False, encoding=encoding)
    for chunk in reader:
        chunk.columns = [c.strip() for c in chunk.columns]
        yield chunk


def build_joint_flow_dataset(
    raw_dir: Path,
    predictor: AutoencoderPredictor,
    chunk_size: int = 100_000,
    files: list[Path] | None = None,
) -> tuple[pd.DataFrame, dict]:
    """Returns (joint_df, report). joint_df columns: src_ip, dst_ip,
    canonical_label, traffic_class, anomaly_score. report tracks row
    counts through each filtering stage for transparency."""
    csv_files = files if files is not None else discover_csv_files(raw_dir)

    frames: list[pd.DataFrame] = []
    total_raw_rows = 0
    total_topology_valid_rows = 0
    total_feature_invalid_rows = 0
    total_scored_rows = 0

    for csv_path in csv_files:
        for raw_chunk in _iter_joint_chunks(csv_path, chunk_size):
            total_raw_rows += len(raw_chunk)
            clean, _stats = clean_chunk(raw_chunk)
            total_topology_valid_rows += len(clean)
            if clean.empty:
                continue

            feature_df = clean[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce")
            feature_df = feature_df.replace([np.inf, -np.inf], np.nan)
            valid_mask = feature_df.notna().all(axis=1)
            total_feature_invalid_rows += int((~valid_mask).sum())
            if not valid_mask.any():
                continue

            clean = clean.loc[valid_mask]
            feature_df = feature_df.loc[valid_mask]

            result = predictor.predict_batch(feature_df)
            total_scored_rows += len(clean)

            frames.append(
                pd.DataFrame(
                    {
                        "src_ip": clean["Source IP"].to_numpy(),
                        "dst_ip": clean["Destination IP"].to_numpy(),
                        "canonical_label": clean["canonical_label"].to_numpy(),
                        "traffic_class": clean["traffic_class"].to_numpy(),
                        "anomaly_score": result["anomaly_score"],
                    }
                )
            )

    joint_df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=["src_ip", "dst_ip", "canonical_label", "traffic_class", "anomaly_score"]
    )
    report = {
        "files_processed": len(csv_files),
        "total_raw_rows": total_raw_rows,
        "total_topology_valid_rows": total_topology_valid_rows,
        "total_feature_invalid_rows_dropped": total_feature_invalid_rows,
        "total_scored_rows": total_scored_rows,
    }
    return joint_df, report


def attach_graph_context(joint_df: pd.DataFrame, graph: nx.DiGraph) -> pd.DataFrame:
    """Adds edge_attack_ratio, edge_attack_flow_count, edge_flow_count,
    edge_first_seen, edge_last_seen, edge_attack_label_count columns via a
    vectorized left-merge against the graph's (already-aggregated, ~114K
    row) edge list -- not a per-row Python lookup, which would not scale
    to millions of joint_df rows. Every row here comes from the same
    dataset the graph was built from, so a missing edge lookup should not
    occur in practice; rows without a match get the documented neutral
    defaults (NaN, treated by risk_engine.normalize as "no graph
    evidence") rather than raising."""
    edge_rows = [
        {
            "src_ip": u,
            "dst_ip": v,
            "edge_attack_ratio": d.get("attack_ratio"),
            "edge_attack_flow_count": d.get("attack_flow_count"),
            "edge_flow_count": d.get("flow_count"),
            "edge_first_seen": d.get("first_seen"),
            "edge_last_seen": d.get("last_seen"),
            "edge_attack_label_count": len(d.get("attack_labels", [])),
        }
        for u, v, d in graph.edges(data=True)
    ]
    edge_df = pd.DataFrame(edge_rows)
    return joint_df.merge(edge_df, on=["src_ip", "dst_ip"], how="left")


def derive_scale_parameters(graph: nx.DiGraph) -> dict:
    """Empirically derives attack_activity_scale and temporal_scale_hours
    from the real attack graph, so risk_engine.config's normalization
    constants are grounded in observed data rather than guessed."""
    attack_counts = [d["attack_flow_count"] for _, _, d in graph.edges(data=True) if d.get("attack_flow_count", 0) > 0]
    activity_scale = float(np.percentile(attack_counts, 95)) if attack_counts else 1.0

    durations_hours = []
    for _, _, d in graph.edges(data=True):
        if d.get("flow_count", 0) <= 1 or not d.get("first_seen") or not d.get("last_seen"):
            continue
        start = pd.Timestamp(d["first_seen"])
        end = pd.Timestamp(d["last_seen"])
        durations_hours.append((end - start).total_seconds() / 3600.0)
    temporal_scale = float(np.percentile(durations_hours, 95)) if durations_hours else 24.0

    return {
        "attack_activity_scale": round(activity_scale, 2),
        "temporal_scale_hours": round(temporal_scale, 2),
        "derivation": {
            "attack_activity_scale": "95th percentile of attack_flow_count across edges with attack_flow_count > 0",
            "temporal_scale_hours": "95th percentile of (last_seen - first_seen) in hours across edges with flow_count > 1",
            "edges_used_for_activity_scale": len(attack_counts),
            "edges_used_for_temporal_scale": len(durations_hours),
        },
    }
