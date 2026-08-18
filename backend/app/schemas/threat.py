"""Combined read-model for the "Live Threats" table (section 9) --
purely a join/projection over Event + Detection + RiskAssessment for
display; the underlying tables still keep raw/derived data separate
(section 5)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ThreatRowOut(BaseModel):
    event_id: int
    timestamp: datetime
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    protocol: int | None
    canonical_attack_label: str | None
    anomaly_score: float | None
    is_anomaly: bool | None
    risk_score: float | None
    risk_level: str | None
    event_source: str
