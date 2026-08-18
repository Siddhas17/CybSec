"""Evaluation utilities for the risk engine, run against the real (not
synthetic) flow dataset produced by risk_engine.data_bridge. Section 11/12
of the phase instructions: measure behavior, don't tune weights against
whatever split is used for final reporting.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from risk_engine.config import HIGH_RISK_THRESHOLD, RiskEngineConfig
from risk_engine.schemas import FlowRiskContext
from risk_engine.scoring import score_event

ATTACK_CLASS = "ATTACK"
BENIGN_CLASS = "BENIGN"


def _none_if_missing(value):
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return value


def score_dataframe(df: pd.DataFrame, config: RiskEngineConfig) -> pd.DataFrame:
    """Applies score_event() to every row. df must have `anomaly_score`
    and the edge_* columns from data_bridge.attach_graph_context (missing
    edge context, i.e. NaN, is treated as "no graph evidence" per
    risk_engine.normalize's documented defaults)."""
    records = df.to_dict("records")
    scores = np.empty(len(records))
    levels: list[str] = []
    rule_counts = np.empty(len(records), dtype=int)

    for i, row in enumerate(records):
        context = FlowRiskContext(
            anomaly_score=row["anomaly_score"],
            edge_attack_ratio=_none_if_missing(row.get("edge_attack_ratio")),
            edge_attack_flow_count=_none_if_missing(row.get("edge_attack_flow_count")),
            edge_flow_count=_none_if_missing(row.get("edge_flow_count")),
            edge_first_seen=row.get("edge_first_seen") if pd.notna(row.get("edge_first_seen")) else None,
            edge_last_seen=row.get("edge_last_seen") if pd.notna(row.get("edge_last_seen")) else None,
            edge_attack_label_count=_none_if_missing(row.get("edge_attack_label_count")),
        )
        result = score_event(context, config)
        scores[i] = result.risk_score
        levels.append(result.risk_level)
        rule_counts[i] = len(result.rules_applied)

    out = df.copy()
    out["risk_score"] = scores
    out["risk_level"] = levels
    out["rules_applied_count"] = rule_counts
    return out


def score_distribution_summary(scored_df: pd.DataFrame) -> dict:
    s = scored_df["risk_score"]
    return {
        "count": int(len(s)),
        "mean": float(s.mean()),
        "median": float(s.median()),
        "std": float(s.std()),
        "min": float(s.min()),
        "max": float(s.max()),
    }


def risk_level_distribution(scored_df: pd.DataFrame) -> dict:
    return scored_df["risk_level"].value_counts().to_dict()


def benign_vs_attack_separation(scored_df: pd.DataFrame) -> dict:
    benign = scored_df.loc[scored_df["traffic_class"] == BENIGN_CLASS, "risk_score"]
    attack = scored_df.loc[scored_df["traffic_class"] == ATTACK_CLASS, "risk_score"]
    return {
        "benign": {"count": int(len(benign)), "mean": float(benign.mean()), "median": float(benign.median())},
        "attack": {"count": int(len(attack)), "mean": float(attack.mean()), "median": float(attack.median())},
    }


def per_attack_risk_table(scored_df: pd.DataFrame, high_risk_threshold: float = HIGH_RISK_THRESHOLD) -> pd.DataFrame:
    """One row per canonical attack category (BENIGN excluded), mirroring
    the per-attack table style from docs/autoencoder.md."""
    attack_df = scored_df[scored_df["traffic_class"] == ATTACK_CLASS]
    rows = [
        {
            "attack_type": label,
            "sample_count": int(len(group)),
            "mean_risk_score": float(group["risk_score"].mean()),
            "median_risk_score": float(group["risk_score"].median()),
            "high_risk_rate": float((group["risk_score"] >= high_risk_threshold).mean()),
        }
        for label, group in attack_df.groupby("canonical_label")
    ]
    return pd.DataFrame(rows).sort_values("sample_count", ascending=False).reset_index(drop=True)


def high_risk_precision_recall(scored_df: pd.DataFrame, threshold: float = HIGH_RISK_THRESHOLD) -> dict:
    """"High-risk" := risk_score >= threshold. Ground truth: traffic_class
    == ATTACK. Same positive-class convention as ml/evaluation/threshold_analysis.py."""
    y_true = (scored_df["traffic_class"] == ATTACK_CLASS).to_numpy()
    y_pred = (scored_df["risk_score"] >= threshold).to_numpy()

    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    fn = int(np.sum(y_true & ~y_pred))
    tn = int(np.sum(~y_true & ~y_pred))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "high_risk_threshold": threshold,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def edge_volume_context_by_category(scored_df: pd.DataFrame, categories: list[str], small_edge_threshold: int = 5) -> dict:
    """For each category, reports the distribution of edge_flow_count --
    quantifying how much a category's detection relies on high-volume
    edges (where the scored flow is a negligible fraction of the edge's
    own aggregate stats) versus low-volume edges (where the flow's own
    label can dominate its edge's attack_ratio -- see docs/risk_engine.md
    "Important methodological caveat"). small_edge_threshold flows or
    fewer counts as "small" for this check."""
    result = {}
    for category in categories:
        group = scored_df[scored_df["canonical_label"] == category]
        if len(group) == 0:
            result[category] = {"sample_count": 0}
            continue
        counts = group["edge_flow_count"].dropna()
        result[category] = {
            "sample_count": int(len(group)),
            "median_edge_flow_count": float(counts.median()) if len(counts) else None,
            "fraction_on_small_edges": float((counts <= small_edge_threshold).mean()) if len(counts) else None,
            "small_edge_threshold": small_edge_threshold,
        }
    return result


def compare_with_anomaly_alone(
    scored_df: pd.DataFrame,
    anomaly_threshold: float,
    categories_of_interest: list[str],
    high_risk_threshold: float = HIGH_RISK_THRESHOLD,
) -> dict:
    """For each attack category, compares the detection rate using (a) the
    autoencoder's own is_anomaly flag alone (anomaly_score >= threshold)
    against (b) the full risk engine's high-risk flag (risk_score >=
    high_risk_threshold). Positive `improvement` means graph context
    raised more flows of that category above the high-risk bar than the
    anomaly score alone would have flagged as anomalous -- section 12 of
    the phase instructions. Reported for every category actually present,
    not cherry-picked."""
    df = scored_df.copy()
    df["anomaly_flagged"] = df["anomaly_score"] >= anomaly_threshold
    df["risk_flagged"] = df["risk_score"] >= high_risk_threshold

    result = {}
    for category in categories_of_interest:
        group = df[df["canonical_label"] == category]
        if len(group) == 0:
            result[category] = {"sample_count": 0}
            continue
        anomaly_rate = float(group["anomaly_flagged"].mean())
        risk_rate = float(group["risk_flagged"].mean())
        result[category] = {
            "sample_count": int(len(group)),
            "anomaly_alone_detection_rate": anomaly_rate,
            "risk_engine_detection_rate": risk_rate,
            "improvement": round(risk_rate - anomaly_rate, 4),
        }
    return result
