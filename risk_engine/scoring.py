"""Combines the five normalized factors into a deterministic, bounded,
explainable 1-10 risk score.

    risk_raw = sum(weight[name] * normalized_factor[name] for name in factors)   # in [0,1]
    risk_score = 1 + 9 * risk_raw                                                # linear calibration to [1,10]
    risk_score = clip(risk_score + sum(rule bonuses/penalties that fire), 1, 10)  # context rules (section 7)

Every step is a pure function of (context, config) -- no hidden state, no
randomness, so the same input always produces the same output (tested in
tests/test_risk_engine_scoring.py).
"""

from __future__ import annotations

from risk_engine.config import RiskEngineConfig, risk_level_for
from risk_engine.explanations import build_explanation
from risk_engine.normalize import (
    anomaly_severity,
    attack_activity_norm,
    attack_context_norm,
    edge_attack_ratio_norm,
    temporal_persistence_norm,
)
from risk_engine.schemas import FlowRiskContext, NormalizedFactors, RiskResult


def normalize_factors(context: FlowRiskContext, config: RiskEngineConfig) -> NormalizedFactors:
    return NormalizedFactors(
        anomaly_severity=anomaly_severity(context.anomaly_score, config.anomaly_threshold),
        edge_attack_ratio=edge_attack_ratio_norm(context.edge_attack_ratio),
        attack_activity=attack_activity_norm(context.edge_attack_flow_count, config.attack_activity_scale),
        temporal_persistence=temporal_persistence_norm(
            context.edge_first_seen, context.edge_last_seen, config.temporal_scale_hours
        ),
        attack_context=attack_context_norm(context.edge_attack_label_count, config.attack_label_cap),
    )


def compute_risk_raw(factors: NormalizedFactors, config: RiskEngineConfig) -> float:
    values = factors.as_dict()
    return sum(config.weights[name] * values[name] for name in config.weights)


def calibrate_to_1_10(risk_raw: float) -> float:
    return 1.0 + 9.0 * max(0.0, min(1.0, risk_raw))


def apply_context_rules(
    calibrated_score: float, context: FlowRiskContext, factors: NormalizedFactors, config: RiskEngineConfig
) -> tuple[float, list[str]]:
    """Three small, transparent, additive adjustments (section 7) -- never
    multiplicative, never more than the three listed here. Order is fixed
    for determinism; the final clip to [1,10] happens after all rules."""
    score = calibrated_score
    applied: list[str] = []

    flow_count = context.edge_flow_count or 0
    attack_flow_count = context.edge_attack_flow_count or 0

    if (context.edge_attack_ratio or 0.0) >= config.repeated_attack_edge_ratio and flow_count >= config.repeated_attack_min_flows:
        score += config.repeated_attack_bonus
        applied.append("repeated_attack_heavy_communication")

    if factors.anomaly_severity >= config.high_anomaly_severity:
        score += config.high_anomaly_bonus
        applied.append("very_high_anomaly")

    if (
        attack_flow_count <= config.isolated_max_attack_flows
        and flow_count <= config.isolated_max_total_flows
        and factors.anomaly_severity < config.isolated_max_anomaly_severity
    ):
        score -= config.isolated_penalty
        applied.append("isolated_low_volume_weak_evidence")

    return max(1.0, min(10.0, score)), applied


def score_event(context: FlowRiskContext, config: RiskEngineConfig | None = None) -> RiskResult:
    """The main scoring interface. Deterministic: identical (context,
    config) always produces an identical RiskResult."""
    config = config or RiskEngineConfig()

    factors = normalize_factors(context, config)
    risk_raw = compute_risk_raw(factors, config)
    calibrated = calibrate_to_1_10(risk_raw)
    final_score, rules_applied = apply_context_rules(calibrated, context, factors, config)

    factor_dicts, reason = build_explanation(factors, config, rules_applied)

    return RiskResult(
        risk_score=round(final_score, 4),
        risk_level=risk_level_for(final_score),
        factors=factor_dicts,
        rules_applied=rules_applied,
        reason=reason,
        config_version=config.version,
    )
