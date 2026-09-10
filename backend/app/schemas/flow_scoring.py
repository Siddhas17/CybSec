"""Pydantic schemas for POST /api/v1/agents/flow-score -- deliberately
separate from schemas/telemetry.py, which is reserved for raw psutil
connection telemetry and is never scored (see
backend.app.services.agent_service.ingest_telemetry_batch()'s docstring:
"section 19's explicit ML firewall"). This schema instead mirrors
backend.app.services.analytical_pipeline.TelemetryEvent's fields, since
that is exactly what the endpoint reconstructs from the request.
"""

from __future__ import annotations

import math
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from victim_agent.flow import CICIDS_FEATURE_NAMES

_EXPECTED_FEATURE_NAMES = frozenset(CICIDS_FEATURE_NAMES)


class VictimFlowScoreIn(BaseModel):
    """Exactly the fields needed to reconstruct a TelemetryEvent from a
    completed victim_agent.flow.Flow -- the Flow object itself never
    crosses the network, only its already-computed output does."""

    source_ip: str
    destination_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str  # victim_agent.flow.Flow.protocol's own vocabulary: "TCP"/"UDP"/"ICMP"/"IP-PROTO-<n>"
    timestamp: datetime
    features: dict[str, float]

    @field_validator("features")
    @classmethod
    def _check_features(cls, v: dict[str, float]) -> dict[str, float]:
        actual = set(v.keys())
        if actual != _EXPECTED_FEATURE_NAMES:
            missing = sorted(_EXPECTED_FEATURE_NAMES - actual)
            unexpected = sorted(actual - _EXPECTED_FEATURE_NAMES)
            raise ValueError(
                "features must contain exactly the 67 CICIDS2017 feature names "
                f"(missing={missing}, unexpected={unexpected})"
            )
        for name, value in v.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"feature {name!r} must be numeric, got {type(value).__name__}")
            if math.isnan(value) or math.isinf(value):
                raise ValueError(f"feature {name!r} must be a finite number, got {value}")
        return v


class VictimFlowScoreOut(BaseModel):
    """Mirrors backend.app.services.analytical_pipeline.DetectionResult --
    score-only, nothing persisted (see api/v1/flow_scoring.py's router
    docstring)."""

    anomaly_score: float
    reconstruction_error: float
    is_anomaly: bool
    threshold_used: float
    risk_score: float
    risk_level: str
    factors: list[dict]
    rules_applied: list[str]
    reason: str
    imputed_features: list[str]
    graph_context_used: bool
