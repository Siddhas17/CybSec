"""Normalization formulas for every risk-engine input signal, each
documented and bounded to [0, 1].

Anomaly severity in particular does NOT use anomaly_score / max(dataset
score), because CICIDS2017's reconstruction-error distribution is
extremely heavy-tailed (BENIGN validation error alone: mean 0.33, std
156, max 87,376 -- see docs/autoencoder.md section 7) -- dividing by the
maximum would make almost every real score collapse to ~0 and a single
extreme outlier would dominate the scale. See
docs/risk_engine.md "Anomaly severity normalization" for the comparison
against a percentile-based alternative that motivated this choice.
"""

from __future__ import annotations

import math


def anomaly_severity(anomaly_score: float, threshold: float) -> float:
    """Threshold-relative, saturating severity: 1 - exp(-score/threshold).

    score=0            -> 0.0
    score=threshold     -> 1 - e^-1 ~ 0.632
    score=3*threshold    -> 1 - e^-3 ~ 0.950
    score->infinity       -> approaches 1.0 (never reaches it)

    Bounded in [0, 1) for any non-negative score; robust to arbitrarily
    large outliers by construction (exponential decay), unlike a linear
    ratio against a fixed maximum.
    """
    if threshold <= 0:
        raise ValueError(f"threshold must be > 0, got {threshold}")
    if anomaly_score < 0:
        raise ValueError(f"anomaly_score must be >= 0, got {anomaly_score}")
    return 1.0 - math.exp(-anomaly_score / threshold)


def edge_attack_ratio_norm(edge_attack_ratio: float | None) -> float:
    """Already in [0,1] by construction (attack_graph.schemas.EdgeAccumulator.attack_ratio).
    Missing graph context (no edge found for this IP pair) normalizes to
    0.0 -- documented neutral default, not a claim of confirmed benign
    behavior."""
    if edge_attack_ratio is None:
        return 0.0
    return max(0.0, min(1.0, edge_attack_ratio))


def attack_activity_norm(edge_attack_flow_count: int | None, activity_scale: float) -> float:
    """Log-saturating normalization of absolute attack-flow volume on the
    edge: min(1, log1p(count) / log1p(scale)). `activity_scale` is a
    persisted reference constant (see risk_engine.config), not re-derived
    per call -- typically a high percentile of attack_flow_count across
    the real attack graph's edges, so a "typical high-volume attack edge"
    saturates this component near 1.0."""
    if activity_scale <= 0:
        raise ValueError(f"activity_scale must be > 0, got {activity_scale}")
    if edge_attack_flow_count is None or edge_attack_flow_count <= 0:
        return 0.0
    return min(1.0, math.log1p(edge_attack_flow_count) / math.log1p(activity_scale))


def temporal_persistence_norm(first_seen: str | None, last_seen: str | None, temporal_scale_hours: float) -> float:
    """Linear-capped normalization of an edge's observed activity span
    (last_seen - first_seen) against a persisted reference duration.
    Returns 0.0 if either timestamp is missing (no persistence evidence)."""
    if temporal_scale_hours <= 0:
        raise ValueError(f"temporal_scale_hours must be > 0, got {temporal_scale_hours}")
    if not first_seen or not last_seen:
        return 0.0
    from datetime import datetime

    start = datetime.fromisoformat(first_seen)
    end = datetime.fromisoformat(last_seen)
    duration_hours = max(0.0, (end - start).total_seconds() / 3600.0)
    return min(1.0, duration_hours / temporal_scale_hours)


def attack_context_norm(edge_attack_label_count: int | None, attack_label_cap: int) -> float:
    """Normalized diversity of *historically observed* attack categories
    on this edge (attack_graph edge attribute `attack_labels`), capped at
    `attack_label_cap` distinct categories. Deliberately NOT the current
    flow's own ground-truth label -- using that would be circular for a
    detector (see docs/risk_engine.md "Why attack_context uses edge
    history, not the flow's own label"). Missing/zero -> 0.0."""
    if attack_label_cap <= 0:
        raise ValueError(f"attack_label_cap must be > 0, got {attack_label_cap}")
    if edge_attack_label_count is None or edge_attack_label_count <= 0:
        return 0.0
    return min(1.0, edge_attack_label_count / attack_label_cap)
