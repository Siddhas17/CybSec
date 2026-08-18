"""Unit tests for risk_engine.scoring: weighted combination, 1-10
calibration/bounding, context rules, risk-level mapping, determinism, and
edge cases (zero attack activity, extreme anomaly scores, missing graph
context, malformed input)."""

import pytest

from risk_engine.config import RiskEngineConfig, risk_level_for
from risk_engine.schemas import FlowRiskContext
from risk_engine.scoring import apply_context_rules, calibrate_to_1_10, compute_risk_raw, normalize_factors, score_event


@pytest.fixture
def config():
    return RiskEngineConfig(anomaly_threshold=0.1, attack_activity_scale=100, temporal_scale_hours=96)


def test_calibrate_to_1_10_bounds():
    assert calibrate_to_1_10(0.0) == 1.0
    assert calibrate_to_1_10(1.0) == 10.0
    assert calibrate_to_1_10(0.5) == 5.5


def test_calibrate_to_1_10_clips_out_of_range_input():
    assert calibrate_to_1_10(-0.5) == 1.0
    assert calibrate_to_1_10(1.5) == 10.0


def test_risk_level_for_boundaries():
    assert risk_level_for(1.0) == "Very Low"
    assert risk_level_for(1.99) == "Very Low"
    assert risk_level_for(2.0) == "Low"
    assert risk_level_for(4.0) == "Moderate"
    assert risk_level_for(6.0) == "High"
    assert risk_level_for(8.0) == "Critical"
    assert risk_level_for(10.0) == "Critical"


def test_score_event_result_always_in_1_to_10(config):
    context = FlowRiskContext(anomaly_score=0.0)
    result = score_event(context, config)
    assert 1.0 <= result.risk_score <= 10.0

    context_extreme = FlowRiskContext(
        anomaly_score=1_000_000.0, edge_attack_ratio=1.0, edge_attack_flow_count=10_000, edge_flow_count=10_000
    )
    result_extreme = score_event(context_extreme, config)
    assert 1.0 <= result_extreme.risk_score <= 10.0


def test_score_event_deterministic(config):
    context = FlowRiskContext(anomaly_score=0.5, edge_attack_ratio=0.7, edge_attack_flow_count=50, edge_flow_count=60)
    r1 = score_event(context, config)
    r2 = score_event(context, config)
    assert r1.risk_score == r2.risk_score
    assert r1.risk_level == r2.risk_level
    assert r1.factors == r2.factors
    assert r1.reason == r2.reason


def test_increasing_anomaly_score_increases_risk_monotonically(config):
    base = FlowRiskContext(anomaly_score=0.01)
    higher = FlowRiskContext(anomaly_score=0.5)
    assert score_event(higher, config).risk_score > score_event(base, config).risk_score


def test_increasing_edge_attack_ratio_increases_risk(config):
    low_ratio = FlowRiskContext(anomaly_score=0.05, edge_attack_ratio=0.1, edge_flow_count=5, edge_attack_flow_count=1)
    high_ratio = FlowRiskContext(anomaly_score=0.05, edge_attack_ratio=0.9, edge_flow_count=5, edge_attack_flow_count=1)
    assert score_event(high_ratio, config).risk_score > score_event(low_ratio, config).risk_score


def test_zero_attack_activity_does_not_crash_and_yields_low_component(config):
    context = FlowRiskContext(anomaly_score=0.01, edge_attack_flow_count=0, edge_flow_count=100, edge_attack_ratio=0.0)
    factors = normalize_factors(context, config)
    assert factors.attack_activity == 0.0
    result = score_event(context, config)
    assert result.risk_level in {"Very Low", "Low"}


def test_extremely_large_anomaly_score_still_bounded(config):
    # By design, anomaly_severity alone (weight 0.4, no corroborating graph
    # context) cannot push risk_raw above 0.4 -- an extreme anomaly score
    # with zero graph evidence lands at "Moderate", not "Critical". This is
    # the intended behavior of a multi-signal engine (see docs/risk_engine.md):
    # a single signal, however extreme, should not alone reach the top of
    # the scale without corroboration.
    context = FlowRiskContext(anomaly_score=87_376.0)  # the real BENIGN validation max, see docs/autoencoder.md
    result = score_event(context, config)
    assert 1.0 <= result.risk_score <= 10.0
    assert result.risk_level == "Moderate"
    assert "very_high_anomaly" in result.rules_applied


def test_missing_graph_context_falls_back_to_neutral_defaults(config):
    context = FlowRiskContext(anomaly_score=0.3)  # no edge_* fields at all
    factors = normalize_factors(context, config)
    assert factors.edge_attack_ratio == 0.0
    assert factors.attack_activity == 0.0
    assert factors.temporal_persistence == 0.0
    assert factors.attack_context == 0.0
    result = score_event(context, config)
    assert 1.0 <= result.risk_score <= 10.0


def test_malformed_input_negative_anomaly_score_rejected():
    with pytest.raises(ValueError):
        FlowRiskContext(anomaly_score=-1.0)


def test_malformed_input_out_of_range_attack_ratio_rejected():
    with pytest.raises(ValueError):
        FlowRiskContext(anomaly_score=0.1, edge_attack_ratio=1.5)


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        RiskEngineConfig(weights={"anomaly_severity": 0.5, "edge_attack_ratio": 0.6, "attack_activity": 0.0, "temporal_persistence": 0.0, "attack_context": 0.0})


def test_repeated_attack_heavy_communication_rule_fires(config):
    factors = normalize_factors(
        FlowRiskContext(anomaly_score=0.01, edge_attack_ratio=0.8, edge_flow_count=20, edge_attack_flow_count=16),
        config,
    )
    score, rules = apply_context_rules(
        5.0, FlowRiskContext(anomaly_score=0.01, edge_attack_ratio=0.8, edge_flow_count=20, edge_attack_flow_count=16), factors, config
    )
    assert "repeated_attack_heavy_communication" in rules
    assert score == pytest.approx(5.5)


def test_isolated_low_volume_rule_reduces_score(config):
    context = FlowRiskContext(anomaly_score=0.02, edge_attack_ratio=0.5, edge_flow_count=1, edge_attack_flow_count=1)
    factors = normalize_factors(context, config)
    score, rules = apply_context_rules(4.0, context, factors, config)
    assert "isolated_low_volume_weak_evidence" in rules
    assert score == pytest.approx(3.5)


def test_high_anomaly_rule_fires_and_reason_mentions_it(config):
    context = FlowRiskContext(anomaly_score=5.0)  # >> threshold=0.1, severity saturates near 1
    result = score_event(context, config)
    assert "very_high_anomaly" in result.rules_applied
    assert "adjusted for" in result.reason


def test_explanation_factors_sum_matches_risk_raw(config):
    context = FlowRiskContext(anomaly_score=0.3, edge_attack_ratio=0.6, edge_flow_count=10, edge_attack_flow_count=5)
    factors = normalize_factors(context, config)
    risk_raw = compute_risk_raw(factors, config)
    result = score_event(context, config)
    contributions_sum = sum(f["contribution"] for f in result.factors)
    assert contributions_sum == pytest.approx(risk_raw, abs=1e-3)
