from __future__ import annotations

from pydantic import BaseModel


class SummaryOut(BaseModel):
    total_events: int
    active_threats: int  # is_anomaly=True detections in the retained window
    high_risk_events: int  # risk_score >= high_risk_threshold
    anomaly_count: int
    benign_count: int
    last_ingested_at: str | None
    system_health: str


class AttacksByTypeOut(BaseModel):
    attack_type: str
    count: int


class RiskDistributionBucket(BaseModel):
    risk_level: str
    count: int


class TimelinePoint(BaseModel):
    bucket: str  # ISO timestamp, hour-truncated
    event_count: int
    attack_count: int


class TopNodeOut(BaseModel):
    ip: str
    attack_flow_count: int
    total_flow_count: int


class ModelInfoOut(BaseModel):
    preprocessing_version: str
    autoencoder_version: str
    autoencoder_threshold: float
    attack_graph_version: str
    risk_engine_version: str
    risk_engine_weights: dict[str, float]
