"""Unit tests for risk_engine.explanations: factor list structure and
reason-string generation."""

from risk_engine.config import RiskEngineConfig
from risk_engine.explanations import build_explanation
from risk_engine.schemas import NormalizedFactors


def test_factor_list_has_all_five_named_entries_sorted_by_contribution():
    config = RiskEngineConfig()
    factors = NormalizedFactors(
        anomaly_severity=0.9, edge_attack_ratio=0.8, attack_activity=0.1, temporal_persistence=0.05, attack_context=0.0
    )
    factor_dicts, _ = build_explanation(factors, config, rules_applied=[])

    assert {f["name"] for f in factor_dicts} == set(config.weights)
    contributions = [f["contribution"] for f in factor_dicts]
    assert contributions == sorted(contributions, reverse=True)
    assert factor_dicts[0]["name"] == "anomaly_severity"  # 0.9*0.4=0.36, highest


def test_reason_mentions_top_factor_intensity():
    config = RiskEngineConfig()
    factors = NormalizedFactors(anomaly_severity=0.95, edge_attack_ratio=0.9, attack_activity=0.0, temporal_persistence=0.0, attack_context=0.0)
    _, reason = build_explanation(factors, config, rules_applied=[])
    assert "High" in reason
    assert "anomaly deviation" in reason


def test_reason_includes_fired_rules():
    config = RiskEngineConfig()
    factors = NormalizedFactors(anomaly_severity=0.95, edge_attack_ratio=0.9, attack_activity=0.0, temporal_persistence=0.0, attack_context=0.0)
    _, reason = build_explanation(factors, config, rules_applied=["very_high_anomaly"])
    assert "adjusted for" in reason
    assert "extreme anomaly" in reason


def test_reason_handles_all_zero_factors_gracefully():
    config = RiskEngineConfig()
    factors = NormalizedFactors(anomaly_severity=0.0, edge_attack_ratio=0.0, attack_activity=0.0, temporal_persistence=0.0, attack_context=0.0)
    _, reason = build_explanation(factors, config, rules_applied=[])
    assert reason == "No significant risk factors observed"
