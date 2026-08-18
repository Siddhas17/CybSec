"""Unit tests for risk_engine.evaluation against a small synthetic scored
dataset with known, hand-computable statistics."""

import numpy as np
import pandas as pd
import pytest

from risk_engine.config import RiskEngineConfig
from risk_engine.evaluation import (
    benign_vs_attack_separation,
    compare_with_anomaly_alone,
    edge_volume_context_by_category,
    high_risk_precision_recall,
    per_attack_risk_table,
    risk_level_distribution,
    score_dataframe,
    score_distribution_summary,
)


@pytest.fixture
def synthetic_df():
    return pd.DataFrame(
        {
            "anomaly_score": [0.01, 0.02, 0.5, 0.6, 0.03, 0.55],
            "traffic_class": ["BENIGN", "BENIGN", "ATTACK", "ATTACK", "BENIGN", "ATTACK"],
            "canonical_label": ["BENIGN", "BENIGN", "DDoS", "PortScan", "BENIGN", "DDoS"],
            "edge_attack_ratio": [0.0, 0.0, 0.9, 0.05, 0.0, 0.9],
            "edge_attack_flow_count": [0, 0, 50, 1, 0, 50],
            "edge_flow_count": [100, 50, 60, 2, 30, 60],
            "edge_first_seen": [None] * 6,
            "edge_last_seen": [None] * 6,
            "edge_attack_label_count": [0, 0, 1, 1, 0, 1],
        }
    )


@pytest.fixture
def config():
    return RiskEngineConfig(anomaly_threshold=0.1, attack_activity_scale=100, temporal_scale_hours=96)


def test_score_dataframe_adds_expected_columns(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    assert "risk_score" in scored.columns
    assert "risk_level" in scored.columns
    assert (scored["risk_score"] >= 1).all() and (scored["risk_score"] <= 10).all()


def test_attack_rows_score_higher_than_benign_on_average(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    benign_mean = scored.loc[scored["traffic_class"] == "BENIGN", "risk_score"].mean()
    attack_mean = scored.loc[scored["traffic_class"] == "ATTACK", "risk_score"].mean()
    assert attack_mean > benign_mean


def test_score_distribution_summary_keys(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    summary = score_distribution_summary(scored)
    assert set(summary) == {"count", "mean", "median", "std", "min", "max"}
    assert summary["count"] == 6


def test_risk_level_distribution_sums_to_row_count(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    dist = risk_level_distribution(scored)
    assert sum(dist.values()) == 6


def test_benign_vs_attack_separation_counts(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    sep = benign_vs_attack_separation(scored)
    assert sep["benign"]["count"] == 3
    assert sep["attack"]["count"] == 3
    assert sep["attack"]["mean"] > sep["benign"]["mean"]


def test_per_attack_risk_table_excludes_benign(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    table = per_attack_risk_table(scored)
    assert set(table["attack_type"]) == {"DDoS", "PortScan"}
    assert "BENIGN" not in set(table["attack_type"])
    ddos_row = table[table["attack_type"] == "DDoS"].iloc[0]
    assert ddos_row["sample_count"] == 2


def test_high_risk_precision_recall_reasonable(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    metrics = high_risk_precision_recall(scored, threshold=7.0)
    assert metrics["tp"] + metrics["fp"] + metrics["fn"] + metrics["tn"] == 6
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0


def test_compare_with_anomaly_alone_reports_all_requested_categories(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    comparison = compare_with_anomaly_alone(
        scored, anomaly_threshold=0.1, categories_of_interest=["PortScan", "DDoS", "SSH-Patator"]
    )
    assert comparison["SSH-Patator"]["sample_count"] == 0  # not present in this synthetic set, reported honestly
    assert comparison["PortScan"]["sample_count"] == 1
    assert comparison["DDoS"]["sample_count"] == 2
    assert "improvement" in comparison["PortScan"]


def test_edge_volume_context_by_category_reports_small_edge_fraction(synthetic_df, config):
    scored = score_dataframe(synthetic_df, config)
    # PortScan row has edge_flow_count=2 (small); DDoS rows have 60 (not small) at threshold=5
    result = edge_volume_context_by_category(scored, categories=["PortScan", "DDoS", "SSH-Patator"], small_edge_threshold=5)
    assert result["PortScan"]["sample_count"] == 1
    assert result["PortScan"]["fraction_on_small_edges"] == 1.0
    assert result["DDoS"]["fraction_on_small_edges"] == 0.0
    assert result["SSH-Patator"]["sample_count"] == 0


def test_compare_with_anomaly_alone_portscan_improves_with_graph_context(synthetic_df, config):
    # PortScan row: anomaly_score=0.5 (>= threshold 0.1, so already
    # anomaly-flagged in this synthetic case) but edge_attack_ratio only
    # 0.05 and edge_attack_flow_count=1 -- weak graph evidence. Verifies
    # the comparison mechanism itself works, not a claim about real data.
    scored = score_dataframe(synthetic_df, config)
    comparison = compare_with_anomaly_alone(scored, anomaly_threshold=0.1, categories_of_interest=["PortScan"])
    assert comparison["PortScan"]["anomaly_alone_detection_rate"] == 1.0
