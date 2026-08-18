"""Builds the machine-readable factor breakdown and a short human-readable
reason string for a RiskResult. Every score returned by score_event()
carries this -- never just the bare number (section 10 of the phase
instructions)."""

from __future__ import annotations

from risk_engine.config import RiskEngineConfig
from risk_engine.schemas import NormalizedFactors

_FACTOR_DESCRIPTIONS: dict[str, str] = {
    "anomaly_severity": "anomaly deviation",
    "edge_attack_ratio": "attack-heavy communication",
    "attack_activity": "attack traffic volume",
    "temporal_persistence": "sustained activity over time",
    "attack_context": "history of diverse attack categories on this edge",
}

_RULE_DESCRIPTIONS: dict[str, str] = {
    "repeated_attack_heavy_communication": "repeated attack-heavy communication",
    "very_high_anomaly": "an extreme anomaly deviation",
    "isolated_low_volume_weak_evidence": "isolated low-volume evidence (risk reduced)",
}


def _intensity(value: float) -> str:
    if value >= 0.6:
        return "High"
    if value >= 0.3:
        return "Moderate"
    return "Low"


def build_explanation(
    factors: NormalizedFactors, config: RiskEngineConfig, rules_applied: list[str]
) -> tuple[list[dict], str]:
    values = factors.as_dict()
    factor_dicts = [
        {
            "name": name,
            "value": round(values[name], 4),
            "contribution": round(config.weights[name] * values[name], 4),
        }
        for name in config.weights
    ]
    factor_dicts.sort(key=lambda f: f["contribution"], reverse=True)

    top = [f for f in factor_dicts[:2] if f["value"] > 0]
    descriptors = [f"{_intensity(f['value'])} {_FACTOR_DESCRIPTIONS[f['name']]}" for f in top]
    reason = " combined with ".join(descriptors) if descriptors else "No significant risk factors observed"

    if rules_applied:
        rule_text = ", ".join(_RULE_DESCRIPTIONS.get(r, r) for r in rules_applied)
        reason = f"{reason}; adjusted for {rule_text}"

    return factor_dicts, reason
