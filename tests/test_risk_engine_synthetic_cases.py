"""The four representative synthetic cases from the phase instructions
(section 18). These are unit-test fixtures only -- not evidence of real
model performance; real evaluation lives in risk_engine/evaluation.py
against actual data (see docs/risk_engine.md)."""

from risk_engine.config import RiskEngineConfig
from risk_engine.schemas import FlowRiskContext
from risk_engine.scoring import score_event

CONFIG = RiskEngineConfig(anomaly_threshold=0.106125, attack_activity_scale=100, temporal_scale_hours=96)


def test_case1_low_anomaly_benign_graph_context_is_low_risk():
    context = FlowRiskContext(
        anomaly_score=0.01,  # well below threshold
        edge_attack_ratio=0.0,
        edge_attack_flow_count=0,
        edge_flow_count=500,  # a well-established, purely benign edge
    )
    result = score_event(context, CONFIG)
    assert result.risk_level in {"Very Low", "Low"}


def test_case2_high_anomaly_weak_graph_context_is_moderate_or_high():
    context = FlowRiskContext(
        anomaly_score=0.5,  # well above threshold
        edge_attack_ratio=None,  # edge not present in the graph at all
        edge_attack_flow_count=None,
        edge_flow_count=None,
    )
    result = score_event(context, CONFIG)
    assert result.risk_level in {"Moderate", "High"}


def test_case3_high_anomaly_attack_heavy_repeated_edge_is_high_or_critical():
    context = FlowRiskContext(
        anomaly_score=0.6,
        edge_attack_ratio=0.95,
        edge_attack_flow_count=500,
        edge_flow_count=520,
        edge_first_seen="2017-07-03T00:00:00",
        edge_last_seen="2017-07-07T00:00:00",  # full 4-day capture window
        edge_attack_label_count=2,
    )
    result = score_event(context, CONFIG)
    assert result.risk_level in {"High", "Critical"}
    assert "repeated_attack_heavy_communication" in result.rules_applied


def test_case4_low_anomaly_benign_edge_is_very_low_or_low():
    context = FlowRiskContext(
        anomaly_score=0.005,
        edge_attack_ratio=0.0,
        edge_attack_flow_count=0,
        edge_flow_count=1000,
    )
    result = score_event(context, CONFIG)
    assert result.risk_level in {"Very Low", "Low"}


def test_case_ordering_case3_scores_higher_than_case2_scores_higher_than_case1():
    case1 = score_event(FlowRiskContext(anomaly_score=0.01, edge_attack_ratio=0.0, edge_flow_count=500, edge_attack_flow_count=0), CONFIG)
    case2 = score_event(FlowRiskContext(anomaly_score=0.5), CONFIG)
    case3 = score_event(
        FlowRiskContext(
            anomaly_score=0.6,
            edge_attack_ratio=0.95,
            edge_attack_flow_count=500,
            edge_flow_count=520,
            edge_first_seen="2017-07-03T00:00:00",
            edge_last_seen="2017-07-07T00:00:00",
            edge_attack_label_count=2,
        ),
        CONFIG,
    )
    assert case1.risk_score < case2.risk_score < case3.risk_score
