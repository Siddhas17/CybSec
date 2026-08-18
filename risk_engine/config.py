"""Risk-engine configuration: weights, normalization scale parameters, and
context-rule thresholds -- all explicit and persisted, no hidden mutable
state (section 16 of the phase instructions).

Baseline weights (documented rationale, not claimed to be objectively
correct -- see docs/risk_engine.md "Weight selection"):

    anomaly_component:        0.40  -- primary evidence; the autoencoder
                                        is the only signal derived from
                                        the flow's own numeric behavior
    edge_attack_ratio:         0.25  -- strongest graph-derived signal
    attack_activity:           0.15  -- absolute attack volume, distinct
                                        information from the ratio (see
                                        docs/risk_engine.md "double
                                        counting")
    temporal_persistence:      0.10  -- sustained activity over time
    attack_context:            0.10  -- edge's historical attack-category
                                        diversity; deliberately small per
                                        the instruction that category
                                        context should not dominate

Weights sum to 1.0 so risk_raw (a weighted sum of five [0,1] components)
is itself bounded to [0,1] before the 1-10 calibration.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_VERSION = "risk-engine-v1"

DEFAULT_WEIGHTS: dict[str, float] = {
    "anomaly_severity": 0.40,
    "edge_attack_ratio": 0.25,
    "attack_activity": 0.15,
    "temporal_persistence": 0.10,
    "attack_context": 0.10,
}

RISK_LEVELS: list[tuple[float, float, str]] = [
    (1.0, 2.0, "Very Low"),
    (2.0, 4.0, "Low"),
    (4.0, 6.0, "Moderate"),
    (6.0, 8.0, "High"),
    (8.0, 10.0001, "Critical"),
]
# Ranges are [low, high); the doc-facing bucket labels (section 6 of the
# phase instructions) are 1-2/3-4/5-6/7-8/9-10 on integer risk scores --
# expressed here as continuous half-open intervals so any real-valued
# risk_score in [1,10] maps to exactly one level without a gap at the
# boundaries.

HIGH_RISK_THRESHOLD = 7.0


@dataclass
class RiskEngineConfig:
    version: str = CONFIG_VERSION
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    # Normalization parameters -- must be derived from real data and
    # persisted, not re-guessed per run. See risk_engine.data_bridge for
    # how these are computed from the Phase 2 attack graph.
    anomaly_threshold: float = 0.106125  # from ml/models/artifacts/autoencoder/threshold.json
    attack_activity_scale: float = 100.0  # 95th percentile of edge attack_flow_count, see data_bridge
    temporal_scale_hours: float = 96.0  # reference duration for temporal persistence normalization
    attack_label_cap: int = 3  # distinct attack categories on an edge at which attack_context saturates

    # Context rule thresholds (section 7)
    repeated_attack_edge_ratio: float = 0.7
    repeated_attack_min_flows: int = 10
    repeated_attack_bonus: float = 0.5
    high_anomaly_severity: float = 0.9
    high_anomaly_bonus: float = 0.5
    isolated_max_attack_flows: int = 1
    isolated_max_total_flows: int = 2
    isolated_max_anomaly_severity: float = 0.5
    isolated_penalty: float = 0.5

    def __post_init__(self) -> None:
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Risk engine weights must sum to 1.0, got {total}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "RiskEngineConfig":
        return cls(**data)

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "RiskEngineConfig":
        return cls.from_dict(json.loads(Path(path).read_text()))


def risk_level_for(score: float) -> str:
    for low, high, label in RISK_LEVELS:
        if low <= score < high:
            return label
    raise ValueError(f"risk_score {score} outside the defined 1-10 range")
