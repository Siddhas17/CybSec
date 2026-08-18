"""Input/output data structures for the risk engine.

FlowRiskContext is deliberately narrow: every field is either the
autoencoder's raw output or a statistic already present on an attack_graph
edge (attack_graph.schemas -- see docs/attack_graph.md section 5). Nothing
here is fabricated (no CVSS scores, no vulnerability data, no inferred
compromise state).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FlowRiskContext:
    """One flow (or one edge, when used as a representative aggregate) to
    be scored. Graph fields are optional -- a flow between an IP pair not
    present in the attack graph (e.g. never seen elsewhere) still gets a
    score, using anomaly evidence alone plus documented neutral defaults
    for the missing graph signals."""

    anomaly_score: float  # raw reconstruction error from ml.models.autoencoder.reconstruction_error
    edge_attack_ratio: float | None = None  # attack_flow_count / flow_count on this src->dst edge, [0,1]
    edge_attack_flow_count: int | None = None
    edge_flow_count: int | None = None
    edge_first_seen: str | None = None  # ISO 8601, from the attack_graph edge
    edge_last_seen: str | None = None
    edge_attack_label_count: int | None = None  # distinct historical canonical attack labels seen on this edge

    def __post_init__(self) -> None:
        if self.anomaly_score < 0:
            raise ValueError(f"anomaly_score must be >= 0 (it's a mean squared error), got {self.anomaly_score}")
        if self.edge_attack_ratio is not None and not (0.0 <= self.edge_attack_ratio <= 1.0):
            raise ValueError(f"edge_attack_ratio must be in [0,1], got {self.edge_attack_ratio}")


@dataclass
class NormalizedFactors:
    """Every scoring signal after normalization to [0, 1]. Kept as its own
    type (rather than a plain dict) so scoring.py and explanations.py share
    one definition of "the five components"."""

    anomaly_severity: float
    edge_attack_ratio: float
    attack_activity: float
    temporal_persistence: float
    attack_context: float

    def as_dict(self) -> dict:
        return {
            "anomaly_severity": self.anomaly_severity,
            "edge_attack_ratio": self.edge_attack_ratio,
            "attack_activity": self.attack_activity,
            "temporal_persistence": self.temporal_persistence,
            "attack_context": self.attack_context,
        }


@dataclass
class RiskResult:
    risk_score: float  # 1-10
    risk_level: str  # Very Low / Low / Moderate / High / Critical
    factors: list[dict] = field(default_factory=list)  # [{"name", "value", "contribution"}, ...]
    rules_applied: list[str] = field(default_factory=list)
    reason: str = ""
    config_version: str = ""

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "factors": self.factors,
            "rules_applied": self.rules_applied,
            "reason": self.reason,
            "config_version": self.config_version,
        }
