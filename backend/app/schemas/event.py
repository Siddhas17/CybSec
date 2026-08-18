"""Pydantic schemas for the canonical event data contract (section 5):
raw event data, derived ML result, derived graph context, and derived
risk assessment are kept as distinct nested objects, never merged into
one opaque blob."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class DetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    anomaly_score: float
    reconstruction_error: float
    is_anomaly: bool
    threshold_used: float
    model_version_id: int


class RiskFactorOut(BaseModel):
    name: str
    value: float
    contribution: float


class RiskAssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    risk_score: float
    risk_level: str
    factors: list[RiskFactorOut]
    rules_applied: list[str]
    reason: str
    risk_config_version_id: int


class GraphContextOut(BaseModel):
    """Optional -- not every event's IP pair has attack-graph context
    (section 5: "do not assume every field is available for every
    event")."""

    edge_attack_ratio: float | None = None
    edge_attack_flow_count: int | None = None
    edge_flow_count: int | None = None
    edge_first_seen: datetime | None = None
    edge_last_seen: datetime | None = None
    edge_attack_label_count: int | None = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_uid: str
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    protocol: int | None
    canonical_attack_label: str | None
    traffic_class: str | None
    source: str
    status: str
    created_at: datetime


class EventDetailOut(EventOut):
    """Full threat-details view: raw event + derived detection + derived
    risk assessment + derived graph context, each clearly separated."""

    detection: DetectionOut | None = None
    risk_assessment: RiskAssessmentOut | None = None
    graph_context: GraphContextOut | None = None


class TestEventCreate(BaseModel):
    """Input for POST /api/test-events -- a controlled test event, always
    explicitly labeled as such (never presented as live detection)."""

    source_ip: str
    source_port: int | None = None
    destination_ip: str
    destination_port: int | None = None
    protocol: int | None = None
    features: dict[str, float] = {}
    canonical_attack_label: str | None = None
