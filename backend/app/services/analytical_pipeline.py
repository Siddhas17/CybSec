"""TelemetryEvent -> AnalyticalPipeline -> DetectionResult (section 18).

This is the one place the backend calls into ml/ and risk_engine/ to score
a flow. It has no dependency on FastAPI, SQLAlchemy, or MySQL -- a future
live sensor phase can construct a TelemetryEvent and call
AnalyticalPipeline.score() exactly the same way offline ingestion and the
test-events endpoint already do here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import numpy as np

from ml.models.inference import AutoencoderPredictor
from risk_engine.config import RiskEngineConfig
from risk_engine.schemas import FlowRiskContext
from risk_engine.scoring import score_event


@dataclass
class TelemetryEvent:
    """A flow ready for scoring -- the same shape whether it comes from
    offline dataset replay, a controlled test event, or (in a future
    phase) a live sensor."""

    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: int | None = None
    timestamp: datetime | None = None
    features: dict[str, float] = field(default_factory=dict)
    canonical_attack_label: str | None = None


@dataclass
class GraphContext:
    edge_attack_ratio: float | None = None
    edge_attack_flow_count: int | None = None
    edge_flow_count: int | None = None
    edge_first_seen: str | None = None
    edge_last_seen: str | None = None
    edge_attack_label_count: int | None = None

    def is_empty(self) -> bool:
        return self.edge_attack_ratio is None and self.edge_flow_count is None


@dataclass
class DetectionResult:
    anomaly_score: float
    reconstruction_error: float
    is_anomaly: bool
    threshold_used: float
    risk_score: float
    risk_level: str
    factors: list[dict]
    rules_applied: list[str]
    reason: str
    graph_context: GraphContext
    imputed_features: list[str]


class AnalyticalPipeline:
    """Wraps the persisted autoencoder + risk engine. Never fits/trains
    anything -- both are loaded read-only (backend.app.services.model_registry)."""

    def __init__(self, predictor: AutoencoderPredictor, risk_config: RiskEngineConfig):
        self.predictor = predictor
        self.risk_config = risk_config

    def _build_feature_vector(self, event: TelemetryEvent) -> tuple[np.ndarray, list[str]]:
        """Any feature name not supplied on the event is filled with the
        scaler's training-mean value for that feature (a documented,
        disclosed imputation -- never a fabricated score; see
        `imputed_features` on the result, which the API surfaces so a
        partially-specified test event is never mistaken for a real
        observed flow)."""
        feature_names = self.predictor.feature_names
        means = self.predictor.scaler.mean_
        values: list[float] = []
        imputed: list[str] = []
        for i, name in enumerate(feature_names):
            if name in event.features:
                values.append(float(event.features[name]))
            else:
                values.append(float(means[i]))
                imputed.append(name)
        return np.array(values, dtype="float64"), imputed

    def score(self, event: TelemetryEvent, graph_context: GraphContext | None = None) -> DetectionResult:
        graph_context = graph_context or GraphContext()
        feature_vector, imputed = self._build_feature_vector(event)

        prediction = self.predictor.predict(feature_vector)

        risk_context = FlowRiskContext(
            anomaly_score=prediction["anomaly_score"],
            edge_attack_ratio=graph_context.edge_attack_ratio,
            edge_attack_flow_count=graph_context.edge_attack_flow_count,
            edge_flow_count=graph_context.edge_flow_count,
            edge_first_seen=graph_context.edge_first_seen,
            edge_last_seen=graph_context.edge_last_seen,
            edge_attack_label_count=graph_context.edge_attack_label_count,
        )
        risk_result = score_event(risk_context, self.risk_config)

        return DetectionResult(
            anomaly_score=prediction["anomaly_score"],
            reconstruction_error=prediction["reconstruction_error"],
            is_anomaly=prediction["is_anomaly"],
            threshold_used=self.predictor.threshold,
            risk_score=risk_result.risk_score,
            risk_level=risk_result.risk_level,
            factors=risk_result.factors,
            rules_applied=risk_result.rules_applied,
            reason=risk_result.reason,
            graph_context=graph_context,
            imputed_features=imputed,
        )
